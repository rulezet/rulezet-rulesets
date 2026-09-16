rule TTP_XOR_WriteProcessMemory_28ec {
  strings:
    $key_28ec = { 7f 9e [2] 4d bc [2] 4b 89 [2] 65 89 [2] 5a 95 }

  condition:
    any of them
}