rule TTP_XOR_WriteProcessMemory_32ec {
  strings:
    $key_32ec = { 65 9e [2] 57 bc [2] 51 89 [2] 7f 89 [2] 40 95 }

  condition:
    any of them
}