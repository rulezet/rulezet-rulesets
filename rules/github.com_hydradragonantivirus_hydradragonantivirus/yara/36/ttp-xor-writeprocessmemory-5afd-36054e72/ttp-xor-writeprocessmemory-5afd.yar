rule TTP_XOR_WriteProcessMemory_5afd {
  strings:
    $key_5afd = { 0d 8f [2] 3f ad [2] 39 98 [2] 17 98 [2] 28 84 }

  condition:
    any of them
}