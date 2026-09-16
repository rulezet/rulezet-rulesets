rule TTP_XOR_WriteProcessMemory_8fd1 {
  strings:
    $key_8fd1 = { d8 a3 [2] ea 81 [2] ec b4 [2] c2 b4 [2] fd a8 }

  condition:
    any of them
}