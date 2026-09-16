rule TTP_XOR_WriteProcessMemory_cba7 {
  strings:
    $key_cba7 = { 9c d5 [2] ae f7 [2] a8 c2 [2] 86 c2 [2] b9 de }

  condition:
    any of them
}