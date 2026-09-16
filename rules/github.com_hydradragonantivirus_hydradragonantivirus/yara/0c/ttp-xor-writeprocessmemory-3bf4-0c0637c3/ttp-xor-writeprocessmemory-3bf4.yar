rule TTP_XOR_WriteProcessMemory_3bf4 {
  strings:
    $key_3bf4 = { 6c 86 [2] 5e a4 [2] 58 91 [2] 76 91 [2] 49 8d }

  condition:
    any of them
}