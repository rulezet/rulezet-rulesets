rule TTP_XOR_WriteProcessMemory_7718 {
  strings:
    $key_7718 = { 20 6a [2] 12 48 [2] 14 7d [2] 3a 7d [2] 05 61 }

  condition:
    any of them
}