rule TTP_XOR_WriteProcessMemory_1e39 {
  strings:
    $key_1e39 = { 49 4b [2] 7b 69 [2] 7d 5c [2] 53 5c [2] 6c 40 }

  condition:
    any of them
}