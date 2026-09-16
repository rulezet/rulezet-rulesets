rule TTP_XOR_WriteProcessMemory_c799 {
  strings:
    $key_c799 = { 90 eb [2] a2 c9 [2] a4 fc [2] 8a fc [2] b5 e0 }

  condition:
    any of them
}