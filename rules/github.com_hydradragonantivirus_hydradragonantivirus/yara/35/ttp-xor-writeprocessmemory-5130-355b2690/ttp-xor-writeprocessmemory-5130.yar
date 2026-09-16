rule TTP_XOR_WriteProcessMemory_5130 {
  strings:
    $key_5130 = { 06 42 [2] 34 60 [2] 32 55 [2] 1c 55 [2] 23 49 }

  condition:
    any of them
}