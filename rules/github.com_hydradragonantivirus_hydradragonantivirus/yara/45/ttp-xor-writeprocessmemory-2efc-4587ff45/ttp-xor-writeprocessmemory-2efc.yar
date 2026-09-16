rule TTP_XOR_WriteProcessMemory_2efc {
  strings:
    $key_2efc = { 79 8e [2] 4b ac [2] 4d 99 [2] 63 99 [2] 5c 85 }

  condition:
    any of them
}