rule TTP_XOR_WriteProcessMemory_1e03 {
  strings:
    $key_1e03 = { 49 71 [2] 7b 53 [2] 7d 66 [2] 53 66 [2] 6c 7a }

  condition:
    any of them
}