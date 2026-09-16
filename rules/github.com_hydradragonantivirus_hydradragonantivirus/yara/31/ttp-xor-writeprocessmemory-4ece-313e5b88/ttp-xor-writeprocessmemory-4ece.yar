rule TTP_XOR_WriteProcessMemory_4ece {
  strings:
    $key_4ece = { 19 bc [2] 2b 9e [2] 2d ab [2] 03 ab [2] 3c b7 }

  condition:
    any of them
}