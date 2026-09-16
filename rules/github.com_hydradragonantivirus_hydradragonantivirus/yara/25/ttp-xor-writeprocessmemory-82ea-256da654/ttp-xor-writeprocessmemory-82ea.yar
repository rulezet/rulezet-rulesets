rule TTP_XOR_WriteProcessMemory_82ea {
  strings:
    $key_82ea = { d5 98 [2] e7 ba [2] e1 8f [2] cf 8f [2] f0 93 }

  condition:
    any of them
}