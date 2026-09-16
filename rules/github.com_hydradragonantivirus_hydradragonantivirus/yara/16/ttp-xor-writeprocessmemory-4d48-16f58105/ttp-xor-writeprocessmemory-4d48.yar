rule TTP_XOR_WriteProcessMemory_4d48 {
  strings:
    $key_4d48 = { 1a 3a [2] 28 18 [2] 2e 2d [2] 00 2d [2] 3f 31 }

  condition:
    any of them
}