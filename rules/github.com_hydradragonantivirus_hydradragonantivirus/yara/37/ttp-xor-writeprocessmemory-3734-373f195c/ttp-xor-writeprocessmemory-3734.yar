rule TTP_XOR_WriteProcessMemory_3734 {
  strings:
    $key_3734 = { 60 46 [2] 52 64 [2] 54 51 [2] 7a 51 [2] 45 4d }

  condition:
    any of them
}