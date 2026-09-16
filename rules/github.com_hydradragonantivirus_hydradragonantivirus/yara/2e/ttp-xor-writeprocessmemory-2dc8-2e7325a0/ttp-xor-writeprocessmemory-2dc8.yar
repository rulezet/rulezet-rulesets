rule TTP_XOR_WriteProcessMemory_2dc8 {
  strings:
    $key_2dc8 = { 7a ba [2] 48 98 [2] 4e ad [2] 60 ad [2] 5f b1 }

  condition:
    any of them
}