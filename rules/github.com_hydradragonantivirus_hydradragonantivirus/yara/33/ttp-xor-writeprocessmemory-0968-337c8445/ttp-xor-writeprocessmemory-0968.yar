rule TTP_XOR_WriteProcessMemory_0968 {
  strings:
    $key_0968 = { 5e 1a [2] 6c 38 [2] 6a 0d [2] 44 0d [2] 7b 11 }

  condition:
    any of them
}