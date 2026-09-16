rule TTP_XOR_WriteProcessMemory_3968 {
  strings:
    $key_3968 = { 6e 1a [2] 5c 38 [2] 5a 0d [2] 74 0d [2] 4b 11 }

  condition:
    any of them
}