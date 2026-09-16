rule TTP_XOR_WriteProcessMemory_2610 {
  strings:
    $key_2610 = { 71 62 [2] 43 40 [2] 45 75 [2] 6b 75 [2] 54 69 }

  condition:
    any of them
}