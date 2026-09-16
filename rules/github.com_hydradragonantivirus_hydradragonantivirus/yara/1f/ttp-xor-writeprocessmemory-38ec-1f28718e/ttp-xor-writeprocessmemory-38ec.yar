rule TTP_XOR_WriteProcessMemory_38ec {
  strings:
    $key_38ec = { 6f 9e [2] 5d bc [2] 5b 89 [2] 75 89 [2] 4a 95 }

  condition:
    any of them
}