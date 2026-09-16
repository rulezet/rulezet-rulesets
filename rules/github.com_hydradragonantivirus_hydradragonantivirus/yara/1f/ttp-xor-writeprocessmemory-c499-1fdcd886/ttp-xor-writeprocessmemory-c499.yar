rule TTP_XOR_WriteProcessMemory_c499 {
  strings:
    $key_c499 = { 93 eb [2] a1 c9 [2] a7 fc [2] 89 fc [2] b6 e0 }

  condition:
    any of them
}