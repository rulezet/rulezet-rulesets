rule TTP_XOR_WriteProcessMemory_e911 {
  strings:
    $key_e911 = { be 63 [2] 8c 41 [2] 8a 74 [2] a4 74 [2] 9b 68 }

  condition:
    any of them
}