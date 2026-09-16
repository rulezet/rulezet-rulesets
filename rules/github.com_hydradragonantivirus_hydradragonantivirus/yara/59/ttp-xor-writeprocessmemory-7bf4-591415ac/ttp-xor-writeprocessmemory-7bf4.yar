rule TTP_XOR_WriteProcessMemory_7bf4 {
  strings:
    $key_7bf4 = { 2c 86 [2] 1e a4 [2] 18 91 [2] 36 91 [2] 09 8d }

  condition:
    any of them
}