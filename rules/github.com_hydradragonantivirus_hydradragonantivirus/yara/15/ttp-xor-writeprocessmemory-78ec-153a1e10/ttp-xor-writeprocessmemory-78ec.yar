rule TTP_XOR_WriteProcessMemory_78ec {
  strings:
    $key_78ec = { 2f 9e [2] 1d bc [2] 1b 89 [2] 35 89 [2] 0a 95 }

  condition:
    any of them
}