rule TTP_XOR_WriteProcessMemory_8ff9 {
  strings:
    $key_8ff9 = { d8 8b [2] ea a9 [2] ec 9c [2] c2 9c [2] fd 80 }

  condition:
    any of them
}