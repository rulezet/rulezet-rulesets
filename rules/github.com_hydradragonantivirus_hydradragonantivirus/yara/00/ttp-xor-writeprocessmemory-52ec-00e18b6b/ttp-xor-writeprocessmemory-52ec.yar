rule TTP_XOR_WriteProcessMemory_52ec {
  strings:
    $key_52ec = { 05 9e [2] 37 bc [2] 31 89 [2] 1f 89 [2] 20 95 }

  condition:
    any of them
}