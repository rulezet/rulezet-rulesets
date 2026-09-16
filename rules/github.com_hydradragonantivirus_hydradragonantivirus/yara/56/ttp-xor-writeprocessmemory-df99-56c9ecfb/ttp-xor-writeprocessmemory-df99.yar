rule TTP_XOR_WriteProcessMemory_df99 {
  strings:
    $key_df99 = { 88 eb [2] ba c9 [2] bc fc [2] 92 fc [2] ad e0 }

  condition:
    any of them
}