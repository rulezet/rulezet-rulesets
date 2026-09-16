rule TTP_XOR_WriteProcessMemory_0c50 {
  strings:
    $key_0c50 = { 5b 22 [2] 69 00 [2] 6f 35 [2] 41 35 [2] 7e 29 }

  condition:
    any of them
}