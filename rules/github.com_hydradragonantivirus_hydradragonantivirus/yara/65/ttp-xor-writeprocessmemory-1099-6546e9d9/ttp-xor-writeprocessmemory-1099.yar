rule TTP_XOR_WriteProcessMemory_1099 {
  strings:
    $key_1099 = { 47 eb [2] 75 c9 [2] 73 fc [2] 5d fc [2] 62 e0 }

  condition:
    any of them
}