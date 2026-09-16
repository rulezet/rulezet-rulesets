rule TTP_XOR_WriteProcessMemory_3253 {
  strings:
    $key_3253 = { 65 21 [2] 57 03 [2] 51 36 [2] 7f 36 [2] 40 2a }

  condition:
    any of them
}