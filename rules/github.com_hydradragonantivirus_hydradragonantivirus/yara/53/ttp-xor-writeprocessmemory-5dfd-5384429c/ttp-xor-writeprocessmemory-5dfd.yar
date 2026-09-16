rule TTP_XOR_WriteProcessMemory_5dfd {
  strings:
    $key_5dfd = { 0a 8f [2] 38 ad [2] 3e 98 [2] 10 98 [2] 2f 84 }

  condition:
    any of them
}