rule TTP_XOR_WriteProcessMemory_f318 {
  strings:
    $key_f318 = { a4 6a [2] 96 48 [2] 90 7d [2] be 7d [2] 81 61 }

  condition:
    any of them
}