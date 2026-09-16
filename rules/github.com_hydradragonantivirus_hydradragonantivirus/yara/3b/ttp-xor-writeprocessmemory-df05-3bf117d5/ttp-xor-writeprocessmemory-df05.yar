rule TTP_XOR_WriteProcessMemory_df05 {
  strings:
    $key_df05 = { 88 77 [2] ba 55 [2] bc 60 [2] 92 60 [2] ad 7c }

  condition:
    any of them
}