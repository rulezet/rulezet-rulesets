rule TTP_XOR_WriteProcessMemory_5220 {
  strings:
    $key_5220 = { 05 52 [2] 37 70 [2] 31 45 [2] 1f 45 [2] 20 59 }

  condition:
    any of them
}