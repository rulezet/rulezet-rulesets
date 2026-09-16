rule TTP_XOR_WriteProcessMemory_95bf {
  strings:
    $key_95bf = { c2 cd [2] f0 ef [2] f6 da [2] d8 da [2] e7 c6 }

  condition:
    any of them
}