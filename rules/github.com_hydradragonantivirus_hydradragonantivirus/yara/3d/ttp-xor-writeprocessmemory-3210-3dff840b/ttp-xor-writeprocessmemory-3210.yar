rule TTP_XOR_WriteProcessMemory_3210 {
  strings:
    $key_3210 = { 65 62 [2] 57 40 [2] 51 75 [2] 7f 75 [2] 40 69 }

  condition:
    any of them
}