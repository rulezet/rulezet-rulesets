rule TTP_XOR_WriteProcessMemory_843f {
  strings:
    $key_843f = { d3 4d [2] e1 6f [2] e7 5a [2] c9 5a [2] f6 46 }

  condition:
    any of them
}