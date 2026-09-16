rule TTP_XOR_WriteProcessMemory_4bf4 {
  strings:
    $key_4bf4 = { 1c 86 [2] 2e a4 [2] 28 91 [2] 06 91 [2] 39 8d }

  condition:
    any of them
}