rule TTP_XOR_WriteProcessMemory_5ffd {
  strings:
    $key_5ffd = { 08 8f [2] 3a ad [2] 3c 98 [2] 12 98 [2] 2d 84 }

  condition:
    any of them
}