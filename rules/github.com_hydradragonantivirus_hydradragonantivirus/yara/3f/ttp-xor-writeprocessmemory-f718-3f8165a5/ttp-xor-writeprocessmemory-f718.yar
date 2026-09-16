rule TTP_XOR_WriteProcessMemory_f718 {
  strings:
    $key_f718 = { a0 6a [2] 92 48 [2] 94 7d [2] ba 7d [2] 85 61 }

  condition:
    any of them
}