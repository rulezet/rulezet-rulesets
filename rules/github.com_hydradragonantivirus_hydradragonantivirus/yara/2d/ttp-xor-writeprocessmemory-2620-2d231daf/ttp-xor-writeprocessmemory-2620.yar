rule TTP_XOR_WriteProcessMemory_2620 {
  strings:
    $key_2620 = { 71 52 [2] 43 70 [2] 45 45 [2] 6b 45 [2] 54 59 }

  condition:
    any of them
}