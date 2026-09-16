rule TTP_XOR_WriteProcessMemory_8f41 {
  strings:
    $key_8f41 = { d8 33 [2] ea 11 [2] ec 24 [2] c2 24 [2] fd 38 }

  condition:
    any of them
}