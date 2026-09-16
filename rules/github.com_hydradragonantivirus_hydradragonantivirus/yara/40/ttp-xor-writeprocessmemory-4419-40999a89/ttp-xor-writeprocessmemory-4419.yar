rule TTP_XOR_WriteProcessMemory_4419 {
  strings:
    $key_4419 = { 13 6b [2] 21 49 [2] 27 7c [2] 09 7c [2] 36 60 }

  condition:
    any of them
}