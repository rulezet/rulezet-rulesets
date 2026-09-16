rule TTP_XOR_WriteProcessMemory_5cfc {
  strings:
    $key_5cfc = { 0b 8e [2] 39 ac [2] 3f 99 [2] 11 99 [2] 2e 85 }

  condition:
    any of them
}