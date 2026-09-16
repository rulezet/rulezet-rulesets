rule TTP_XOR_WriteProcessMemory_d656 {
  strings:
    $key_d656 = { 81 24 [2] b3 06 [2] b5 33 [2] 9b 33 [2] a4 2f }

  condition:
    any of them
}