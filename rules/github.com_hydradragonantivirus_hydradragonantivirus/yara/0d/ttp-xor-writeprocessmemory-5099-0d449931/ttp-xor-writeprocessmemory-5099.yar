rule TTP_XOR_WriteProcessMemory_5099 {
  strings:
    $key_5099 = { 07 eb [2] 35 c9 [2] 33 fc [2] 1d fc [2] 22 e0 }

  condition:
    any of them
}