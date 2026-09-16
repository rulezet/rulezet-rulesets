rule TTP_XOR_WriteProcessMemory_1e52 {
  strings:
    $key_1e52 = { 49 20 [2] 7b 02 [2] 7d 37 [2] 53 37 [2] 6c 2b }

  condition:
    any of them
}