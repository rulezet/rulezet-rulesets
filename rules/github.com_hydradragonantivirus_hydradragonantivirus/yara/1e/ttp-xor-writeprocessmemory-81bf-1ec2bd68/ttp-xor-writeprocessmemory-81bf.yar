rule TTP_XOR_WriteProcessMemory_81bf {
  strings:
    $key_81bf = { d6 cd [2] e4 ef [2] e2 da [2] cc da [2] f3 c6 }

  condition:
    any of them
}