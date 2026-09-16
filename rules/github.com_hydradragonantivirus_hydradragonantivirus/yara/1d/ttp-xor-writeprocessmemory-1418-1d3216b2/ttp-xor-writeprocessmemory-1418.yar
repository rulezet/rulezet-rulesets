rule TTP_XOR_WriteProcessMemory_1418 {
  strings:
    $key_1418 = { 43 6a [2] 71 48 [2] 77 7d [2] 59 7d [2] 66 61 }

  condition:
    any of them
}