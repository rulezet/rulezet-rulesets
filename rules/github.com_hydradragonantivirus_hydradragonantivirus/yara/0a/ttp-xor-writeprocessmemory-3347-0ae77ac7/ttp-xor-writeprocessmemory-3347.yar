rule TTP_XOR_WriteProcessMemory_3347 {
  strings:
    $key_3347 = { 64 35 [2] 56 17 [2] 50 22 [2] 7e 22 [2] 41 3e }

  condition:
    any of them
}