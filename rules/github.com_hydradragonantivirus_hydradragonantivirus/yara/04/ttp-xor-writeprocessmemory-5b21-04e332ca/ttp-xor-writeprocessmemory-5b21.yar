rule TTP_XOR_WriteProcessMemory_5b21 {
  strings:
    $key_5b21 = { 0c 53 [2] 3e 71 [2] 38 44 [2] 16 44 [2] 29 58 }

  condition:
    any of them
}