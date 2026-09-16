rule TTP_XOR_WriteProcessMemory_1eec {
  strings:
    $key_1eec = { 49 9e [2] 7b bc [2] 7d 89 [2] 53 89 [2] 6c 95 }

  condition:
    any of them
}