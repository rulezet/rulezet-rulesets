rule TTP_XOR_WriteProcessMemory_96bf {
  strings:
    $key_96bf = { c1 cd [2] f3 ef [2] f5 da [2] db da [2] e4 c6 }

  condition:
    any of them
}