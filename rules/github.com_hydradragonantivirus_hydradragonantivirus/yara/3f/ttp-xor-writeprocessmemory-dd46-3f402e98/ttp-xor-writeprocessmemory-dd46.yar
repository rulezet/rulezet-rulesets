rule TTP_XOR_WriteProcessMemory_dd46 {
  strings:
    $key_dd46 = { 8a 34 [2] b8 16 [2] be 23 [2] 90 23 [2] af 3f }

  condition:
    any of them
}