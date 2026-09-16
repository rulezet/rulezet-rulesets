rule TTP_XOR_WriteProcessMemory_6318 {
  strings:
    $key_6318 = { 34 6a [2] 06 48 [2] 00 7d [2] 2e 7d [2] 11 61 }

  condition:
    any of them
}