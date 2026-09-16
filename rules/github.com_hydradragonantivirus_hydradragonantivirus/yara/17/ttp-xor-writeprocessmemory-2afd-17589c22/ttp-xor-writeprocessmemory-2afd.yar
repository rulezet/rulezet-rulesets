rule TTP_XOR_WriteProcessMemory_2afd {
  strings:
    $key_2afd = { 7d 8f [2] 4f ad [2] 49 98 [2] 67 98 [2] 58 84 }

  condition:
    any of them
}