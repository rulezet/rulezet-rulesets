rule TTP_XOR_WriteProcessMemory_df39 {
  strings:
    $key_df39 = { 88 4b [2] ba 69 [2] bc 5c [2] 92 5c [2] ad 40 }

  condition:
    any of them
}