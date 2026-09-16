rule TTP_XOR_WriteProcessMemory_7f18 {
  strings:
    $key_7f18 = { 28 6a [2] 1a 48 [2] 1c 7d [2] 32 7d [2] 0d 61 }

  condition:
    any of them
}