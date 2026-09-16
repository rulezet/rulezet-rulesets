rule TTP_XOR_WriteProcessMemory_1e0c {
  strings:
    $key_1e0c = { 49 7e [2] 7b 5c [2] 7d 69 [2] 53 69 [2] 6c 75 }

  condition:
    any of them
}