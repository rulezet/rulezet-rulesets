rule TTP_XOR_WriteProcessMemory_3632 {
  strings:
    $key_3632 = { 61 40 [2] 53 62 [2] 55 57 [2] 7b 57 [2] 44 4b }

  condition:
    any of them
}