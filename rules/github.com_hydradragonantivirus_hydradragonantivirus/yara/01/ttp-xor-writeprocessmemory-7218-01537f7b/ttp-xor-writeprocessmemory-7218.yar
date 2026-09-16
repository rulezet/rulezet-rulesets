rule TTP_XOR_WriteProcessMemory_7218 {
  strings:
    $key_7218 = { 25 6a [2] 17 48 [2] 11 7d [2] 3f 7d [2] 00 61 }

  condition:
    any of them
}