rule TTP_XOR_WriteProcessMemory_efed {
  strings:
    $key_efed = { b8 9f [2] 8a bd [2] 8c 88 [2] a2 88 [2] 9d 94 }

  condition:
    any of them
}