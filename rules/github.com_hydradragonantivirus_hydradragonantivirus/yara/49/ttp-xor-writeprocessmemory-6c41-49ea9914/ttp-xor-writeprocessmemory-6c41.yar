rule TTP_XOR_WriteProcessMemory_6c41 {
  strings:
    $key_6c41 = { 3b 33 [2] 09 11 [2] 0f 24 [2] 21 24 [2] 1e 38 }

  condition:
    any of them
}