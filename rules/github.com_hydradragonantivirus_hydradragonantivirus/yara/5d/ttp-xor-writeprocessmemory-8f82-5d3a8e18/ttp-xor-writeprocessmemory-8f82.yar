rule TTP_XOR_WriteProcessMemory_8f82 {
  strings:
    $key_8f82 = { d8 f0 [2] ea d2 [2] ec e7 [2] c2 e7 [2] fd fb }

  condition:
    any of them
}