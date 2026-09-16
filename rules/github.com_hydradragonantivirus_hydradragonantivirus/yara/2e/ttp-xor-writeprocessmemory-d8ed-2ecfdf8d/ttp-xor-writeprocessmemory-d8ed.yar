rule TTP_XOR_WriteProcessMemory_d8ed {
  strings:
    $key_d8ed = { 8f 9f [2] bd bd [2] bb 88 [2] 95 88 [2] aa 94 }

  condition:
    any of them
}