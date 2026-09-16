rule TTP_XOR_WriteProcessMemory_1f18 {
  strings:
    $key_1f18 = { 48 6a [2] 7a 48 [2] 7c 7d [2] 52 7d [2] 6d 61 }

  condition:
    any of them
}