rule TTP_XOR_WriteProcessMemory_5538 {
  strings:
    $key_5538 = { 02 4a [2] 30 68 [2] 36 5d [2] 18 5d [2] 27 41 }

  condition:
    any of them
}