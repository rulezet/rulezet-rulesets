rule TTP_XOR_WriteProcessMemory_16f4 {
  strings:
    $key_16f4 = { 41 86 [2] 73 a4 [2] 75 91 [2] 5b 91 [2] 64 8d }

  condition:
    any of them
}