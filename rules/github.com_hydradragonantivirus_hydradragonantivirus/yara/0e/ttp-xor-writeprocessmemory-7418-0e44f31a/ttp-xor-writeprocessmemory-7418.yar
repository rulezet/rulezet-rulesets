rule TTP_XOR_WriteProcessMemory_7418 {
  strings:
    $key_7418 = { 23 6a [2] 11 48 [2] 17 7d [2] 39 7d [2] 06 61 }

  condition:
    any of them
}