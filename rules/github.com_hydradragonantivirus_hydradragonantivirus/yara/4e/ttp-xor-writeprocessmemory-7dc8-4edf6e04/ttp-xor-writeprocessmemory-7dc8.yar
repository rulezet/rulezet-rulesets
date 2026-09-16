rule TTP_XOR_WriteProcessMemory_7dc8 {
  strings:
    $key_7dc8 = { 2a ba [2] 18 98 [2] 1e ad [2] 30 ad [2] 0f b1 }

  condition:
    any of them
}