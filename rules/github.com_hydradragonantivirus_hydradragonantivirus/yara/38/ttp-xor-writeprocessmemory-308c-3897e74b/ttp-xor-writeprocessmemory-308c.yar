rule TTP_XOR_WriteProcessMemory_308c {
  strings:
    $key_308c = { 67 fe [2] 55 dc [2] 53 e9 [2] 7d e9 [2] 42 f5 }

  condition:
    any of them
}