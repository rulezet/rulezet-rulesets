rule TTP_XOR_WriteProcessMemory_0dc8 {
  strings:
    $key_0dc8 = { 5a ba [2] 68 98 [2] 6e ad [2] 40 ad [2] 7f b1 }

  condition:
    any of them
}