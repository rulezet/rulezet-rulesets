rule TTP_XOR_WriteProcessMemory_5efd {
  strings:
    $key_5efd = { 09 8f [2] 3b ad [2] 3d 98 [2] 13 98 [2] 2c 84 }

  condition:
    any of them
}