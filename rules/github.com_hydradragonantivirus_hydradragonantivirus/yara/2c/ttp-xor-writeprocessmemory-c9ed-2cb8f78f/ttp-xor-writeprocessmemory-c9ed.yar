rule TTP_XOR_WriteProcessMemory_c9ed {
  strings:
    $key_c9ed = { 9e 9f [2] ac bd [2] aa 88 [2] 84 88 [2] bb 94 }

  condition:
    any of them
}