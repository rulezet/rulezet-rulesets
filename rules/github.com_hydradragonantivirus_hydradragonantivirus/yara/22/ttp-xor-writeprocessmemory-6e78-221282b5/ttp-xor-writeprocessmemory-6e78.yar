rule TTP_XOR_WriteProcessMemory_6e78 {
  strings:
    $key_6e78 = { 39 0a [2] 0b 28 [2] 0d 1d [2] 23 1d [2] 1c 01 }

  condition:
    any of them
}