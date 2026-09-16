rule TTP_XOR_WriteProcessMemory_3c25 {
  strings:
    $key_3c25 = { 6b 57 [2] 59 75 [2] 5f 40 [2] 71 40 [2] 4e 5c }

  condition:
    any of them
}