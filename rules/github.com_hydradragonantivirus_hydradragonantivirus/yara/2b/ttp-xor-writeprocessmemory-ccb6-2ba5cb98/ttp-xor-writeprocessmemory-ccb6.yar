rule TTP_XOR_WriteProcessMemory_ccb6 {
  strings:
    $key_ccb6 = { 9b c4 [2] a9 e6 [2] af d3 [2] 81 d3 [2] be cf }

  condition:
    any of them
}