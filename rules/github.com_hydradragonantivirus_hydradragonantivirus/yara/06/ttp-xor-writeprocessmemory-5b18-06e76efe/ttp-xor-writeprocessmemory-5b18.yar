rule TTP_XOR_WriteProcessMemory_5b18 {
  strings:
    $key_5b18 = { 0c 6a [2] 3e 48 [2] 38 7d [2] 16 7d [2] 29 61 }

  condition:
    any of them
}