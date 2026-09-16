rule TTP_XOR_WriteProcessMemory_0d8c {
  strings:
    $key_0d8c = { 5a fe [2] 68 dc [2] 6e e9 [2] 40 e9 [2] 7f f5 }

  condition:
    any of them
}