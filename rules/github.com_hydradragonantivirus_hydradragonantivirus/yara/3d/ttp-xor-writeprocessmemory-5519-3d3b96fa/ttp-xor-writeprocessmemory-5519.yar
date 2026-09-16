rule TTP_XOR_WriteProcessMemory_5519 {
  strings:
    $key_5519 = { 02 6b [2] 30 49 [2] 36 7c [2] 18 7c [2] 27 60 }

  condition:
    any of them
}