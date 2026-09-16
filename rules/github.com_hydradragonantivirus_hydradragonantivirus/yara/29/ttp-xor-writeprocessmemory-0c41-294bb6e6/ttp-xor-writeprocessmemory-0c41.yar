rule TTP_XOR_WriteProcessMemory_0c41 {
  strings:
    $key_0c41 = { 5b 33 [2] 69 11 [2] 6f 24 [2] 41 24 [2] 7e 38 }

  condition:
    any of them
}