rule TTP_XOR_WriteProcessMemory_6efc {
  strings:
    $key_6efc = { 39 8e [2] 0b ac [2] 0d 99 [2] 23 99 [2] 1c 85 }

  condition:
    any of them
}