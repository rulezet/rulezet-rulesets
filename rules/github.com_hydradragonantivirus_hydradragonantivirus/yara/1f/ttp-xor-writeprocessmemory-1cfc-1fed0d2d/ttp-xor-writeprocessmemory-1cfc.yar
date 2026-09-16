rule TTP_XOR_WriteProcessMemory_1cfc {
  strings:
    $key_1cfc = { 4b 8e [2] 79 ac [2] 7f 99 [2] 51 99 [2] 6e 85 }

  condition:
    any of them
}