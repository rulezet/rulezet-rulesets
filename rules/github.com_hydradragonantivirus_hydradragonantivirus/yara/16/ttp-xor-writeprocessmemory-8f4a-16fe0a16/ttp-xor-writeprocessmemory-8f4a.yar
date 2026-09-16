rule TTP_XOR_WriteProcessMemory_8f4a {
  strings:
    $key_8f4a = { d8 38 [2] ea 1a [2] ec 2f [2] c2 2f [2] fd 33 }

  condition:
    any of them
}