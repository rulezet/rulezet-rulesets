rule TTP_XOR_WriteProcessMemory_0ece {
  strings:
    $key_0ece = { 59 bc [2] 6b 9e [2] 6d ab [2] 43 ab [2] 7c b7 }

  condition:
    any of them
}