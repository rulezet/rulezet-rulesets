rule TTP_XOR_WriteProcessMemory_93ec {
  strings:
    $key_93ec = { c4 9e [2] f6 bc [2] f0 89 [2] de 89 [2] e1 95 }

  condition:
    any of them
}