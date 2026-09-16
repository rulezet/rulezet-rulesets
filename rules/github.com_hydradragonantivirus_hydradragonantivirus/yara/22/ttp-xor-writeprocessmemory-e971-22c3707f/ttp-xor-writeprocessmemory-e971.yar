rule TTP_XOR_WriteProcessMemory_e971 {
  strings:
    $key_e971 = { be 03 [2] 8c 21 [2] 8a 14 [2] a4 14 [2] 9b 08 }

  condition:
    any of them
}