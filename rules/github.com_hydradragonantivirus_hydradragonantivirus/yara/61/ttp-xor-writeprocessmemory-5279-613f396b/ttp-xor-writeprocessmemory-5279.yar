rule TTP_XOR_WriteProcessMemory_5279 {
  strings:
    $key_5279 = { 05 0b [2] 37 29 [2] 31 1c [2] 1f 1c [2] 20 00 }

  condition:
    any of them
}