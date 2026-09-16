rule TTP_XOR_WriteProcessMemory_84ea {
  strings:
    $key_84ea = { d3 98 [2] e1 ba [2] e7 8f [2] c9 8f [2] f6 93 }

  condition:
    any of them
}