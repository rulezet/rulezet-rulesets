rule TTP_XOR_WriteProcessMemory_3978 {
  strings:
    $key_3978 = { 6e 0a [2] 5c 28 [2] 5a 1d [2] 74 1d [2] 4b 01 }

  condition:
    any of them
}