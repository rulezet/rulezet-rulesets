rule TTP_XOR_WriteProcessMemory_4317 {
  strings:
    $key_4317 = { 14 65 [2] 26 47 [2] 20 72 [2] 0e 72 [2] 31 6e }

  condition:
    any of them
}