rule TTP_XOR_WriteProcessMemory_7806 {
  strings:
    $key_7806 = { 2f 74 [2] 1d 56 [2] 1b 63 [2] 35 63 [2] 0a 7f }

  condition:
    any of them
}