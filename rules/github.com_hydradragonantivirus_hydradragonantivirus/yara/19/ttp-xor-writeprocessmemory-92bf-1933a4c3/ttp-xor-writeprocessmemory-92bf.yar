rule TTP_XOR_WriteProcessMemory_92bf {
  strings:
    $key_92bf = { c5 cd [2] f7 ef [2] f1 da [2] df da [2] e0 c6 }

  condition:
    any of them
}