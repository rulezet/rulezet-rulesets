rule TTP_XOR_WriteProcessMemory_7c10 {
  strings:
    $key_7c10 = { 2b 62 [2] 19 40 [2] 1f 75 [2] 31 75 [2] 0e 69 }

  condition:
    any of them
}