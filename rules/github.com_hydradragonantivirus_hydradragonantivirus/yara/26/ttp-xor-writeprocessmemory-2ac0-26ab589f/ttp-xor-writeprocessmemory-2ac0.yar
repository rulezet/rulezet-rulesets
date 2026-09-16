rule TTP_XOR_WriteProcessMemory_2ac0 {
  strings:
    $key_2ac0 = { 7d b2 [2] 4f 90 [2] 49 a5 [2] 67 a5 [2] 58 b9 }

  condition:
    any of them
}