rule TTP_XOR_WriteProcessMemory_84bf {
  strings:
    $key_84bf = { d3 cd [2] e1 ef [2] e7 da [2] c9 da [2] f6 c6 }

  condition:
    any of them
}