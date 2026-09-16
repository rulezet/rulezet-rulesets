rule TTP_XOR_WriteProcessMemory_df21 {
  strings:
    $key_df21 = { 88 53 [2] ba 71 [2] bc 44 [2] 92 44 [2] ad 58 }

  condition:
    any of them
}