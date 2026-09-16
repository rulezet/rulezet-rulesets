rule TTP_XOR_WriteProcessMemory_6437 {
  strings:
    $key_6437 = { 33 45 [2] 01 67 [2] 07 52 [2] 29 52 [2] 16 4e }

  condition:
    any of them
}