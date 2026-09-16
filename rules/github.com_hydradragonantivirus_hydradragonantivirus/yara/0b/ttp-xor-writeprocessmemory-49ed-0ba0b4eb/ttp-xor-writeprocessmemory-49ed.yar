rule TTP_XOR_WriteProcessMemory_49ed {
  strings:
    $key_49ed = { 1e 9f [2] 2c bd [2] 2a 88 [2] 04 88 [2] 3b 94 }

  condition:
    any of them
}