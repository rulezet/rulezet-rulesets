rule TTP_XOR_WriteProcessMemory_07f4 {
  strings:
    $key_07f4 = { 50 86 [2] 62 a4 [2] 64 91 [2] 4a 91 [2] 75 8d }

  condition:
    any of them
}