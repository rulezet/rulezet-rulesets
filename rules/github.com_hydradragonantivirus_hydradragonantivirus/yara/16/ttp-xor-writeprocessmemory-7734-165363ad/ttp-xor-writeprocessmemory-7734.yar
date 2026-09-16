rule TTP_XOR_WriteProcessMemory_7734 {
  strings:
    $key_7734 = { 20 46 [2] 12 64 [2] 14 51 [2] 3a 51 [2] 05 4d }

  condition:
    any of them
}