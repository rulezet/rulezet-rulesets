rule TTP_XOR_WriteProcessMemory_6f18 {
  strings:
    $key_6f18 = { 38 6a [2] 0a 48 [2] 0c 7d [2] 22 7d [2] 1d 61 }

  condition:
    any of them
}