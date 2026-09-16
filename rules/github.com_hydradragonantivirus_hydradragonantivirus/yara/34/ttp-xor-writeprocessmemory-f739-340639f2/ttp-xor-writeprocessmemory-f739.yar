rule TTP_XOR_WriteProcessMemory_f739 {
  strings:
    $key_f739 = { a0 4b [2] 92 69 [2] 94 5c [2] ba 5c [2] 85 40 }

  condition:
    any of them
}