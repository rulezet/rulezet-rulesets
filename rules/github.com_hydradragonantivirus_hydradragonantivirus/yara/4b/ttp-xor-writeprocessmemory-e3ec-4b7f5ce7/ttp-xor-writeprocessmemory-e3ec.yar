rule TTP_XOR_WriteProcessMemory_e3ec {
  strings:
    $key_e3ec = { b4 9e [2] 86 bc [2] 80 89 [2] ae 89 [2] 91 95 }

  condition:
    any of them
}