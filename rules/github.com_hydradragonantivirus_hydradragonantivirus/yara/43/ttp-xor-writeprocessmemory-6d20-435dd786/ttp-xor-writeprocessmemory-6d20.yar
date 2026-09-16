rule TTP_XOR_WriteProcessMemory_6d20 {
  strings:
    $key_6d20 = { 3a 52 [2] 08 70 [2] 0e 45 [2] 20 45 [2] 1f 59 }

  condition:
    any of them
}