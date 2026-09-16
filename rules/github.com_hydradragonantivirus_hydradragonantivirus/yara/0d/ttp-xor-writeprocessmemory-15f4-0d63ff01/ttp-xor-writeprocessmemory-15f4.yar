rule TTP_XOR_WriteProcessMemory_15f4 {
  strings:
    $key_15f4 = { 42 86 [2] 70 a4 [2] 76 91 [2] 58 91 [2] 67 8d }

  condition:
    any of them
}