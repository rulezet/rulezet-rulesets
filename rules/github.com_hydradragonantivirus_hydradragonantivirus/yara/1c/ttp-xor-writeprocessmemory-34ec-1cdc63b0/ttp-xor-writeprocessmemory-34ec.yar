rule TTP_XOR_WriteProcessMemory_34ec {
  strings:
    $key_34ec = { 63 9e [2] 51 bc [2] 57 89 [2] 79 89 [2] 46 95 }

  condition:
    any of them
}