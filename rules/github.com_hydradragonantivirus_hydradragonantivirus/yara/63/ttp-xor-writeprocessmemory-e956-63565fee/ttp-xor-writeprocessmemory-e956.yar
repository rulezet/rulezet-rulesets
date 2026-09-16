rule TTP_XOR_WriteProcessMemory_e956 {
  strings:
    $key_e956 = { be 24 [2] 8c 06 [2] 8a 33 [2] a4 33 [2] 9b 2f }

  condition:
    any of them
}