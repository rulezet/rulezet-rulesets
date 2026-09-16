rule TTP_XOR_WriteProcessMemory_79e2 {
  strings:
    $key_79e2 = { 2e 90 [2] 1c b2 [2] 1a 87 [2] 34 87 [2] 0b 9b }

  condition:
    any of them
}