rule TTP_XOR_WriteProcessMemory_4418 {
  strings:
    $key_4418 = { 13 6a [2] 21 48 [2] 27 7d [2] 09 7d [2] 36 61 }

  condition:
    any of them
}