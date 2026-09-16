rule TTP_XOR_WriteProcessMemory_d699 {
  strings:
    $key_d699 = { 81 eb [2] b3 c9 [2] b5 fc [2] 9b fc [2] a4 e0 }

  condition:
    any of them
}