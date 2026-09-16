rule TTP_XOR_WriteProcessMemory_8f3a {
  strings:
    $key_8f3a = { d8 48 [2] ea 6a [2] ec 5f [2] c2 5f [2] fd 43 }

  condition:
    any of them
}