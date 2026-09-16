rule TTP_XOR_WriteProcessMemory_c199 {
  strings:
    $key_c199 = { 96 eb [2] a4 c9 [2] a2 fc [2] 8c fc [2] b3 e0 }

  condition:
    any of them
}