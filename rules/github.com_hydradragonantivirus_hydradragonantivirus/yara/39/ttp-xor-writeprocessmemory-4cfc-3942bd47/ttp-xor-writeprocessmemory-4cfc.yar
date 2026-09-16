rule TTP_XOR_WriteProcessMemory_4cfc {
  strings:
    $key_4cfc = { 1b 8e [2] 29 ac [2] 2f 99 [2] 01 99 [2] 3e 85 }

  condition:
    any of them
}