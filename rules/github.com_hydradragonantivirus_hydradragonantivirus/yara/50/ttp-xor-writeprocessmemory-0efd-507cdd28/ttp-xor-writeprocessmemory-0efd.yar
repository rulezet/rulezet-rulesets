rule TTP_XOR_WriteProcessMemory_0efd {
  strings:
    $key_0efd = { 59 8f [2] 6b ad [2] 6d 98 [2] 43 98 [2] 7c 84 }

  condition:
    any of them
}