rule TTP_XOR_WriteProcessMemory_3718 {
  strings:
    $key_3718 = { 60 6a [2] 52 48 [2] 54 7d [2] 7a 7d [2] 45 61 }

  condition:
    any of them
}