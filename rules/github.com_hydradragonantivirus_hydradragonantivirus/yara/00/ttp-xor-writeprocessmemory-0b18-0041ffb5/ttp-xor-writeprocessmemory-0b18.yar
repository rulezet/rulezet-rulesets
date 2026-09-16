rule TTP_XOR_WriteProcessMemory_0b18 {
  strings:
    $key_0b18 = { 5c 6a [2] 6e 48 [2] 68 7d [2] 46 7d [2] 79 61 }

  condition:
    any of them
}