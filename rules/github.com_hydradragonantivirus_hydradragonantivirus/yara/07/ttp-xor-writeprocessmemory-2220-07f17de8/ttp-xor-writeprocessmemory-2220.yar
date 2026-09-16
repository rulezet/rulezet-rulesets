rule TTP_XOR_WriteProcessMemory_2220 {
  strings:
    $key_2220 = { 75 52 [2] 47 70 [2] 41 45 [2] 6f 45 [2] 50 59 }

  condition:
    any of them
}