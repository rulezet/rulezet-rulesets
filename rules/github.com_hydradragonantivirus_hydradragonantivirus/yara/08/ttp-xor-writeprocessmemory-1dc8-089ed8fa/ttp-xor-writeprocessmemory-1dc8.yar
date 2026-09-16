rule TTP_XOR_WriteProcessMemory_1dc8 {
  strings:
    $key_1dc8 = { 4a ba [2] 78 98 [2] 7e ad [2] 50 ad [2] 6f b1 }

  condition:
    any of them
}