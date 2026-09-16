rule TTP_XOR_WriteProcessMemory_3efc {
  strings:
    $key_3efc = { 69 8e [2] 5b ac [2] 5d 99 [2] 73 99 [2] 4c 85 }

  condition:
    any of them
}