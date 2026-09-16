rule TTP_XOR_WriteProcessMemory_79e5 {
  strings:
    $key_79e5 = { 2e 97 [2] 1c b5 [2] 1a 80 [2] 34 80 [2] 0b 9c }

  condition:
    any of them
}