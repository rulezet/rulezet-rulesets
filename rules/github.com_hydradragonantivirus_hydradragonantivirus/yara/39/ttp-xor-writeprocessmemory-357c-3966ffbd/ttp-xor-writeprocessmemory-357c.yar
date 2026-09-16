rule TTP_XOR_WriteProcessMemory_357c {
  strings:
    $key_357c = { 62 0e [2] 50 2c [2] 56 19 [2] 78 19 [2] 47 05 }

  condition:
    any of them
}