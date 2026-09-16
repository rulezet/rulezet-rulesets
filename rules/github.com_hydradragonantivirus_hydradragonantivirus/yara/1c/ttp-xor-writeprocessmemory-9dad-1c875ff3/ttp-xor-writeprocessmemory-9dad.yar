rule TTP_XOR_WriteProcessMemory_9dad {
  strings:
    $key_9dad = { ca df [2] f8 fd [2] fe c8 [2] d0 c8 [2] ef d4 }

  condition:
    any of them
}