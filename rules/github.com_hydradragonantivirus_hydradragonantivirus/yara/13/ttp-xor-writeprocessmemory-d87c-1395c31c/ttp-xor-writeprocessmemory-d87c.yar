rule TTP_XOR_WriteProcessMemory_d87c {
  strings:
    $key_d87c = { 8f 0e [2] bd 2c [2] bb 19 [2] 95 19 [2] aa 05 }

  condition:
    any of them
}