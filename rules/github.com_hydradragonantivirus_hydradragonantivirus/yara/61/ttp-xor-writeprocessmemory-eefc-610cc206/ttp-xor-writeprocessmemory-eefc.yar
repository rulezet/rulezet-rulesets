rule TTP_XOR_WriteProcessMemory_eefc {
  strings:
    $key_eefc = { b9 8e [2] 8b ac [2] 8d 99 [2] a3 99 [2] 9c 85 }

  condition:
    any of them
}