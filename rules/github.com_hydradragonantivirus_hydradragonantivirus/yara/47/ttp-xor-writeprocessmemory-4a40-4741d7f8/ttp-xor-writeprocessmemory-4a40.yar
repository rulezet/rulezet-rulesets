rule TTP_XOR_WriteProcessMemory_4a40 {
  strings:
    $key_4a40 = { 1d 32 [2] 2f 10 [2] 29 25 [2] 07 25 [2] 38 39 }

  condition:
    any of them
}