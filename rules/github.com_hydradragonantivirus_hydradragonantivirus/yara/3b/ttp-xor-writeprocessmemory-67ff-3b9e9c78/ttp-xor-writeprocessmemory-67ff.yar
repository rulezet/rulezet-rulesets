rule TTP_XOR_WriteProcessMemory_67ff {
  strings:
    $key_67ff = { 30 8d [2] 02 af [2] 04 9a [2] 2a 9a [2] 15 86 }

  condition:
    any of them
}