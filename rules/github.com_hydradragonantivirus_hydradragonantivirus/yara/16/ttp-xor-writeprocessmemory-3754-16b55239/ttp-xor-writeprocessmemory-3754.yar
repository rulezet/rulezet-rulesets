rule TTP_XOR_WriteProcessMemory_3754 {
  strings:
    $key_3754 = { 60 26 [2] 52 04 [2] 54 31 [2] 7a 31 [2] 45 2d }

  condition:
    any of them
}