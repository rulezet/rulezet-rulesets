rule TTP_XOR_WriteProcessMemory_6e68 {
  strings:
    $key_6e68 = { 39 1a [2] 0b 38 [2] 0d 0d [2] 23 0d [2] 1c 11 }

  condition:
    any of them
}