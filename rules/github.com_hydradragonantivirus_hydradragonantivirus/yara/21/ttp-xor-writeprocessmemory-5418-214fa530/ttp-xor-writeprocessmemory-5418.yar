rule TTP_XOR_WriteProcessMemory_5418 {
  strings:
    $key_5418 = { 03 6a [2] 31 48 [2] 37 7d [2] 19 7d [2] 26 61 }

  condition:
    any of them
}