rule TTP_XOR_WriteProcessMemory_8f0a {
  strings:
    $key_8f0a = { d8 78 [2] ea 5a [2] ec 6f [2] c2 6f [2] fd 73 }

  condition:
    any of them
}