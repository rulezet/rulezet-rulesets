rule TTP_XOR_WriteProcessMemory_89e4 {
  strings:
    $key_89e4 = { de 96 [2] ec b4 [2] ea 81 [2] c4 81 [2] fb 9d }

  condition:
    any of them
}