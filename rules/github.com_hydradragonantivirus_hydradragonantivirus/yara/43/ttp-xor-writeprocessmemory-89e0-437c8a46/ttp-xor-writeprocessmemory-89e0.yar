rule TTP_XOR_WriteProcessMemory_89e0 {
  strings:
    $key_89e0 = { de 92 [2] ec b0 [2] ea 85 [2] c4 85 [2] fb 99 }

  condition:
    any of them
}