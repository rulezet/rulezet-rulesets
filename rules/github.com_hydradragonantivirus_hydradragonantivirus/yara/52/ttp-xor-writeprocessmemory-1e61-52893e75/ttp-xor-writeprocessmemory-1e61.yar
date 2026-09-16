rule TTP_XOR_WriteProcessMemory_1e61 {
  strings:
    $key_1e61 = { 49 13 [2] 7b 31 [2] 7d 04 [2] 53 04 [2] 6c 18 }

  condition:
    any of them
}