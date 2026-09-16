rule TTP_XOR_WriteProcessMemory_84ff {
  strings:
    $key_84ff = { d3 8d [2] e1 af [2] e7 9a [2] c9 9a [2] f6 86 }

  condition:
    any of them
}