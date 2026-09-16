rule TTP_XOR_WriteProcessMemory_14e8 {
  strings:
    $key_14e8 = { 43 9a [2] 71 b8 [2] 77 8d [2] 59 8d [2] 66 91 }

  condition:
    any of them
}