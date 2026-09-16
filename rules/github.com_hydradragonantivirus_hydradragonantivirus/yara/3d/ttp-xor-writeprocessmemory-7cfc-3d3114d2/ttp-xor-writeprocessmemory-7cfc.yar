rule TTP_XOR_WriteProcessMemory_7cfc {
  strings:
    $key_7cfc = { 2b 8e [2] 19 ac [2] 1f 99 [2] 31 99 [2] 0e 85 }

  condition:
    any of them
}