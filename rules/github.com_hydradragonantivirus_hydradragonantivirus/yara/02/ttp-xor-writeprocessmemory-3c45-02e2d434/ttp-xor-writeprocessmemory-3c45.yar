rule TTP_XOR_WriteProcessMemory_3c45 {
  strings:
    $key_3c45 = { 6b 37 [2] 59 15 [2] 5f 20 [2] 71 20 [2] 4e 3c }

  condition:
    any of them
}