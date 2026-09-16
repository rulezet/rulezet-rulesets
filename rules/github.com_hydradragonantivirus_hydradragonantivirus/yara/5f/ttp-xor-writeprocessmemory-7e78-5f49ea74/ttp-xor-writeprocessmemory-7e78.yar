rule TTP_XOR_WriteProcessMemory_7e78 {
  strings:
    $key_7e78 = { 29 0a [2] 1b 28 [2] 1d 1d [2] 33 1d [2] 0c 01 }

  condition:
    any of them
}