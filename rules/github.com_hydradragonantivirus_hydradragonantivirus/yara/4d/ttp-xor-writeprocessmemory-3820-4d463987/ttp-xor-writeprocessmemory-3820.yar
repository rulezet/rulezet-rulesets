rule TTP_XOR_WriteProcessMemory_3820 {
  strings:
    $key_3820 = { 6f 52 [2] 5d 70 [2] 5b 45 [2] 75 45 [2] 4a 59 }

  condition:
    any of them
}