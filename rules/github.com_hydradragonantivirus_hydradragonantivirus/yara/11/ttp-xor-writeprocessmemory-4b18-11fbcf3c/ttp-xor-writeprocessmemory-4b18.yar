rule TTP_XOR_WriteProcessMemory_4b18 {
  strings:
    $key_4b18 = { 1c 6a [2] 2e 48 [2] 28 7d [2] 06 7d [2] 39 61 }

  condition:
    any of them
}