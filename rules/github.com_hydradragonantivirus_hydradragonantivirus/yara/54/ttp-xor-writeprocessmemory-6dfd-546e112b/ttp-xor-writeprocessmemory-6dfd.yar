rule TTP_XOR_WriteProcessMemory_6dfd {
  strings:
    $key_6dfd = { 3a 8f [2] 08 ad [2] 0e 98 [2] 20 98 [2] 1f 84 }

  condition:
    any of them
}