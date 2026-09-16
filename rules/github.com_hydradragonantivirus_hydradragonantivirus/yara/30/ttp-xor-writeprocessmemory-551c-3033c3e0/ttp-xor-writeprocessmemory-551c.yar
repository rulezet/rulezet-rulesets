rule TTP_XOR_WriteProcessMemory_551c {
  strings:
    $key_551c = { 02 6e [2] 30 4c [2] 36 79 [2] 18 79 [2] 27 65 }

  condition:
    any of them
}