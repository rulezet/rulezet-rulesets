rule TTP_XOR_WriteProcessMemory_89a0 {
  strings:
    $key_89a0 = { de d2 [2] ec f0 [2] ea c5 [2] c4 c5 [2] fb d9 }

  condition:
    any of them
}