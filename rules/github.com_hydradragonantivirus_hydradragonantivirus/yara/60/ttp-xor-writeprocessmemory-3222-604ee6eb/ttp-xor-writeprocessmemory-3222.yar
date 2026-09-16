rule TTP_XOR_WriteProcessMemory_3222 {
  strings:
    $key_3222 = { 65 50 [2] 57 72 [2] 51 47 [2] 7f 47 [2] 40 5b }

  condition:
    any of them
}