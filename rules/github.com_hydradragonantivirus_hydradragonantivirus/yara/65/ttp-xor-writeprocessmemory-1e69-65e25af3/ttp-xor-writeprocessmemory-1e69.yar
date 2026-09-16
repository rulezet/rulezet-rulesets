rule TTP_XOR_WriteProcessMemory_1e69 {
  strings:
    $key_1e69 = { 49 1b [2] 7b 39 [2] 7d 0c [2] 53 0c [2] 6c 10 }

  condition:
    any of them
}