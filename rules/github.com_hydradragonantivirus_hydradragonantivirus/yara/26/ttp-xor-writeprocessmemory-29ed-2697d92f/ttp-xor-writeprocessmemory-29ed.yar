rule TTP_XOR_WriteProcessMemory_29ed {
  strings:
    $key_29ed = { 7e 9f [2] 4c bd [2] 4a 88 [2] 64 88 [2] 5b 94 }

  condition:
    any of them
}