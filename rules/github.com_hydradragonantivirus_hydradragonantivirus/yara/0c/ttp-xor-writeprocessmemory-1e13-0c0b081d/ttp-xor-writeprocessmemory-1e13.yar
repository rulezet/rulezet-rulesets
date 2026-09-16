rule TTP_XOR_WriteProcessMemory_1e13 {
  strings:
    $key_1e13 = { 49 61 [2] 7b 43 [2] 7d 76 [2] 53 76 [2] 6c 6a }

  condition:
    any of them
}