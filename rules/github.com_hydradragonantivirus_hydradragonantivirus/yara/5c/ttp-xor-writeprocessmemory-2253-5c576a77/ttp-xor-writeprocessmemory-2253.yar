rule TTP_XOR_WriteProcessMemory_2253 {
  strings:
    $key_2253 = { 75 21 [2] 47 03 [2] 41 36 [2] 6f 36 [2] 50 2a }

  condition:
    any of them
}