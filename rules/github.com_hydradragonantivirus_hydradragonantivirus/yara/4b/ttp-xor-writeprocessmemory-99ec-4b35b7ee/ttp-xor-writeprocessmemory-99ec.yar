rule TTP_XOR_WriteProcessMemory_99ec {
  strings:
    $key_99ec = { ce 9e [2] fc bc [2] fa 89 [2] d4 89 [2] eb 95 }

  condition:
    any of them
}