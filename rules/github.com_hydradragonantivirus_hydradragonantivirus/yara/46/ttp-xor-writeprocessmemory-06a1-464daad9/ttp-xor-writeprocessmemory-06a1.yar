rule TTP_XOR_WriteProcessMemory_06a1 {
  strings:
    $key_06a1 = { 51 d3 [2] 63 f1 [2] 65 c4 [2] 4b c4 [2] 74 d8 }

  condition:
    any of them
}