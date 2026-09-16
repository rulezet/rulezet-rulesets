rule TTP_XOR_WriteProcessMemory_fbad {
  strings:
    $key_fbad = { ac df [2] 9e fd [2] 98 c8 [2] b6 c8 [2] 89 d4 }

  condition:
    any of them
}