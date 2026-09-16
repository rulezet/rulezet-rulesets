rule TTP_XOR_WriteProcessMemory_4155 {
  strings:
    $key_4155 = { 16 27 [2] 24 05 [2] 22 30 [2] 0c 30 [2] 33 2c }

  condition:
    any of them
}