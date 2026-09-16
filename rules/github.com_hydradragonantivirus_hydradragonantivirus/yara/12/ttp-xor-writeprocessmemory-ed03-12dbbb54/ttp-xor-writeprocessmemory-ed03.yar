rule TTP_XOR_WriteProcessMemory_ed03 {
  strings:
    $key_ed03 = { ba 71 [2] 88 53 [2] 8e 66 [2] a0 66 [2] 9f 7a }

  condition:
    any of them
}