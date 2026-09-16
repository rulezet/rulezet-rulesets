rule TTP_XOR_WriteProcessMemory_29e1 {
  strings:
    $key_29e1 = { 7e 93 [2] 4c b1 [2] 4a 84 [2] 64 84 [2] 5b 98 }

  condition:
    any of them
}