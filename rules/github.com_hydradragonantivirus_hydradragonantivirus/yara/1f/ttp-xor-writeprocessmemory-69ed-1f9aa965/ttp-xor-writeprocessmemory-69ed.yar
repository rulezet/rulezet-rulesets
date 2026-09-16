rule TTP_XOR_WriteProcessMemory_69ed {
  strings:
    $key_69ed = { 3e 9f [2] 0c bd [2] 0a 88 [2] 24 88 [2] 1b 94 }

  condition:
    any of them
}