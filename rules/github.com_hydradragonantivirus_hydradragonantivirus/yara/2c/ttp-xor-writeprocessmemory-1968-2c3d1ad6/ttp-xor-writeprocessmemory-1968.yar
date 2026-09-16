rule TTP_XOR_WriteProcessMemory_1968 {
  strings:
    $key_1968 = { 4e 1a [2] 7c 38 [2] 7a 0d [2] 54 0d [2] 6b 11 }

  condition:
    any of them
}