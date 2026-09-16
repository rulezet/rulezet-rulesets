rule TTP_XOR_WriteProcessMemory_6699 {
  strings:
    $key_6699 = { 31 eb [2] 03 c9 [2] 05 fc [2] 2b fc [2] 14 e0 }

  condition:
    any of them
}