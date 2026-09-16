rule TTP_XOR_WriteProcessMemory_3c40 {
  strings:
    $key_3c40 = { 6b 32 [2] 59 10 [2] 5f 25 [2] 71 25 [2] 4e 39 }

  condition:
    any of them
}