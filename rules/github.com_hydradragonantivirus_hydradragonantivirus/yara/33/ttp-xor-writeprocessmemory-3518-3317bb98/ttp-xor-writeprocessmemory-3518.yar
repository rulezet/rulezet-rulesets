rule TTP_XOR_WriteProcessMemory_3518 {
  strings:
    $key_3518 = { 62 6a [2] 50 48 [2] 56 7d [2] 78 7d [2] 47 61 }

  condition:
    any of them
}