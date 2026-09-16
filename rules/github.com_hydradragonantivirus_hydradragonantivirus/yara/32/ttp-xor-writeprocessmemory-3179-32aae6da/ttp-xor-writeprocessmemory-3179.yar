rule TTP_XOR_WriteProcessMemory_3179 {
  strings:
    $key_3179 = { 66 0b [2] 54 29 [2] 52 1c [2] 7c 1c [2] 43 00 }

  condition:
    any of them
}