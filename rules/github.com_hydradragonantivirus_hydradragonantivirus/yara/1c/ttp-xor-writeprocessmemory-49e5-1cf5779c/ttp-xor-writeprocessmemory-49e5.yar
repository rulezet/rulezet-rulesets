rule TTP_XOR_WriteProcessMemory_49e5 {
  strings:
    $key_49e5 = { 1e 97 [2] 2c b5 [2] 2a 80 [2] 04 80 [2] 3b 9c }

  condition:
    any of them
}