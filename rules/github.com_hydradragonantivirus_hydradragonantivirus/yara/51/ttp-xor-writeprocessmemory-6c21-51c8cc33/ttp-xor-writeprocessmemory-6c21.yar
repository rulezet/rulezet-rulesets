rule TTP_XOR_WriteProcessMemory_6c21 {
  strings:
    $key_6c21 = { 3b 53 [2] 09 71 [2] 0f 44 [2] 21 44 [2] 1e 58 }

  condition:
    any of them
}