rule TTP_XOR_WriteProcessMemory_3434 {
  strings:
    $key_3434 = { 63 46 [2] 51 64 [2] 57 51 [2] 79 51 [2] 46 4d }

  condition:
    any of them
}