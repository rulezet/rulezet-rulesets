rule TTP_XOR_WriteProcessMemory_4221 {
  strings:
    $key_4221 = { 15 53 [2] 27 71 [2] 21 44 [2] 0f 44 [2] 30 58 }

  condition:
    any of them
}