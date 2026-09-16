rule TTP_XOR_WriteProcessMemory_79e9 {
  strings:
    $key_79e9 = { 2e 9b [2] 1c b9 [2] 1a 8c [2] 34 8c [2] 0b 90 }

  condition:
    any of them
}