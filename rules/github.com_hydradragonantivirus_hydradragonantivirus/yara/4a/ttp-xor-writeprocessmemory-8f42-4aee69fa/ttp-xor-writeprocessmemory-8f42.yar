rule TTP_XOR_WriteProcessMemory_8f42 {
  strings:
    $key_8f42 = { d8 30 [2] ea 12 [2] ec 27 [2] c2 27 [2] fd 3b }

  condition:
    any of them
}