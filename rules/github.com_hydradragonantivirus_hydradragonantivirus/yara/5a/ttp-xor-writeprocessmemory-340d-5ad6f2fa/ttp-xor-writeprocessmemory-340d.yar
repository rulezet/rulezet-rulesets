rule TTP_XOR_WriteProcessMemory_340d {
  strings:
    $key_340d = { 63 7f [2] 51 5d [2] 57 68 [2] 79 68 [2] 46 74 }

  condition:
    any of them
}