rule TTP_XOR_WriteProcessMemory_2a40 {
  strings:
    $key_2a40 = { 7d 32 [2] 4f 10 [2] 49 25 [2] 67 25 [2] 58 39 }

  condition:
    any of them
}