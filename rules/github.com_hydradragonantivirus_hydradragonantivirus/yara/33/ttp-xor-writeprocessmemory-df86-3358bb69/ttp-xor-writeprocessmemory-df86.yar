rule TTP_XOR_WriteProcessMemory_df86 {
  strings:
    $key_df86 = { 88 f4 [2] ba d6 [2] bc e3 [2] 92 e3 [2] ad ff }

  condition:
    any of them
}