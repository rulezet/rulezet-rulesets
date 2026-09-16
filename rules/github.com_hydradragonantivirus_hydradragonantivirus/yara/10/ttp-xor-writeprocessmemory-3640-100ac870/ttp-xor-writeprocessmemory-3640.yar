rule TTP_XOR_WriteProcessMemory_3640 {
  strings:
    $key_3640 = { 61 32 [2] 53 10 [2] 55 25 [2] 7b 25 [2] 44 39 }

  condition:
    any of them
}