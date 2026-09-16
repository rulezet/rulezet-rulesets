rule TTP_XOR_WriteProcessMemory_1e5c {
  strings:
    $key_1e5c = { 49 2e [2] 7b 0c [2] 7d 39 [2] 53 39 [2] 6c 25 }

  condition:
    any of them
}