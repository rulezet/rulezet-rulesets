rule TTP_XOR_WriteProcessMemory_4d18 {
  strings:
    $key_4d18 = { 1a 6a [2] 28 48 [2] 2e 7d [2] 00 7d [2] 3f 61 }

  condition:
    any of them
}