rule TTP_XOR_WriteProcessMemory_61ce {
  strings:
    $key_61ce = { 36 bc [2] 04 9e [2] 02 ab [2] 2c ab [2] 13 b7 }

  condition:
    any of them
}