rule TTP_XOR_WriteProcessMemory_1220 {
  strings:
    $key_1220 = { 45 52 [2] 77 70 [2] 71 45 [2] 5f 45 [2] 60 59 }

  condition:
    any of them
}