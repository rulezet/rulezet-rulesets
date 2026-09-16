rule TTP_XOR_WriteProcessMemory_238c {
  strings:
    $key_238c = { 74 fe [2] 46 dc [2] 40 e9 [2] 6e e9 [2] 51 f5 }

  condition:
    any of them
}