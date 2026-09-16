rule TTP_XOR_WriteProcessMemory_4132 {
  strings:
    $key_4132 = { 16 40 [2] 24 62 [2] 22 57 [2] 0c 57 [2] 33 4b }

  condition:
    any of them
}