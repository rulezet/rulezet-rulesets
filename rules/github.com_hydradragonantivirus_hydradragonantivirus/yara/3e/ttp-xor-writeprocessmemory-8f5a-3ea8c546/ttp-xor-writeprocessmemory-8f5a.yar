rule TTP_XOR_WriteProcessMemory_8f5a {
  strings:
    $key_8f5a = { d8 28 [2] ea 0a [2] ec 3f [2] c2 3f [2] fd 23 }

  condition:
    any of them
}