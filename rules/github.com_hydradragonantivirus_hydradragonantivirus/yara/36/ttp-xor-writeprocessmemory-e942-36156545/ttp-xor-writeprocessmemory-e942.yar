rule TTP_XOR_WriteProcessMemory_e942 {
  strings:
    $key_e942 = { be 30 [2] 8c 12 [2] 8a 27 [2] a4 27 [2] 9b 3b }

  condition:
    any of them
}