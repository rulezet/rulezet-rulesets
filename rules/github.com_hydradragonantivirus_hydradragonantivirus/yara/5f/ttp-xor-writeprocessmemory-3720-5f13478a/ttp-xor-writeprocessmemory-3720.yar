rule TTP_XOR_WriteProcessMemory_3720 {
  strings:
    $key_3720 = { 60 52 [2] 52 70 [2] 54 45 [2] 7a 45 [2] 45 59 }

  condition:
    any of them
}