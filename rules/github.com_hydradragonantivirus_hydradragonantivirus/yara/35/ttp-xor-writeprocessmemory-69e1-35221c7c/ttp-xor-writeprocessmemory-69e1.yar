rule TTP_XOR_WriteProcessMemory_69e1 {
  strings:
    $key_69e1 = { 3e 93 [2] 0c b1 [2] 0a 84 [2] 24 84 [2] 1b 98 }

  condition:
    any of them
}