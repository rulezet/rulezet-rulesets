rule TTP_XOR_WriteProcessMemory_5699 {
  strings:
    $key_5699 = { 01 eb [2] 33 c9 [2] 35 fc [2] 1b fc [2] 24 e0 }

  condition:
    any of them
}