rule TTP_XOR_WriteProcessMemory_3235 {
  strings:
    $key_3235 = { 65 47 [2] 57 65 [2] 51 50 [2] 7f 50 [2] 40 4c }

  condition:
    any of them
}