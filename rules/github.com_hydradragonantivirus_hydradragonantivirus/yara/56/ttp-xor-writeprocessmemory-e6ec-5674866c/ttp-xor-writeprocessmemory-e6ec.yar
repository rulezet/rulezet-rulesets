rule TTP_XOR_WriteProcessMemory_e6ec {
  strings:
    $key_e6ec = { b1 9e [2] 83 bc [2] 85 89 [2] ab 89 [2] 94 95 }

  condition:
    any of them
}