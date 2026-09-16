rule TTP_XOR_WriteProcessMemory_68e2 {
  strings:
    $key_68e2 = { 3f 90 [2] 0d b2 [2] 0b 87 [2] 25 87 [2] 1a 9b }

  condition:
    any of them
}