rule TTP_XOR_WriteProcessMemory_7918 {
  strings:
    $key_7918 = { 2e 6a [2] 1c 48 [2] 1a 7d [2] 34 7d [2] 0b 61 }

  condition:
    any of them
}