rule TTP_XOR_WriteProcessMemory_1e30 {
  strings:
    $key_1e30 = { 49 42 [2] 7b 60 [2] 7d 55 [2] 53 55 [2] 6c 49 }

  condition:
    any of them
}