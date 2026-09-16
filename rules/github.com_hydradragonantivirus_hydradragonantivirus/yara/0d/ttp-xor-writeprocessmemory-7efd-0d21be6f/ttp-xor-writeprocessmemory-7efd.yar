rule TTP_XOR_WriteProcessMemory_7efd {
  strings:
    $key_7efd = { 29 8f [2] 1b ad [2] 1d 98 [2] 33 98 [2] 0c 84 }

  condition:
    any of them
}