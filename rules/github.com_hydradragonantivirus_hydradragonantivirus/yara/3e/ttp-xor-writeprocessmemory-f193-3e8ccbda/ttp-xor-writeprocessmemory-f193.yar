rule TTP_XOR_WriteProcessMemory_f193 {
  strings:
    $key_f193 = { a6 e1 [2] 94 c3 [2] 92 f6 [2] bc f6 [2] 83 ea }

  condition:
    any of them
}