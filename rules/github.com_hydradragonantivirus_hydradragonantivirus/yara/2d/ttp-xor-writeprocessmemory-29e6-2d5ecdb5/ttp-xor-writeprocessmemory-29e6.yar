rule TTP_XOR_WriteProcessMemory_29e6 {
  strings:
    $key_29e6 = { 7e 94 [2] 4c b6 [2] 4a 83 [2] 64 83 [2] 5b 9f }

  condition:
    any of them
}