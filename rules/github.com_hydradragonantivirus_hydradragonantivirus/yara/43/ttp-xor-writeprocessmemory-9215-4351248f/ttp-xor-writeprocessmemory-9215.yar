rule TTP_XOR_WriteProcessMemory_9215 {
  strings:
    $key_9215 = { c5 67 [2] f7 45 [2] f1 70 [2] df 70 [2] e0 6c }

  condition:
    any of them
}