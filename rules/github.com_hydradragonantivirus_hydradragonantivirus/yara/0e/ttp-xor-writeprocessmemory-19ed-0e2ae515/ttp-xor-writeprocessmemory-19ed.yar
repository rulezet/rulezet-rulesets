rule TTP_XOR_WriteProcessMemory_19ed {
  strings:
    $key_19ed = { 4e 9f [2] 7c bd [2] 7a 88 [2] 54 88 [2] 6b 94 }

  condition:
    any of them
}