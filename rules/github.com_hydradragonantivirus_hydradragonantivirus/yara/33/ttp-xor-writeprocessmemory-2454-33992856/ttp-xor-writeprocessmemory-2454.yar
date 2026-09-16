rule TTP_XOR_WriteProcessMemory_2454 {
  strings:
    $key_2454 = { 73 26 [2] 41 04 [2] 47 31 [2] 69 31 [2] 56 2d }

  condition:
    any of them
}