rule TTP_XOR_WriteProcessMemory_cbb9 {
  strings:
    $key_cbb9 = { 9c cb [2] ae e9 [2] a8 dc [2] 86 dc [2] b9 c0 }

  condition:
    any of them
}