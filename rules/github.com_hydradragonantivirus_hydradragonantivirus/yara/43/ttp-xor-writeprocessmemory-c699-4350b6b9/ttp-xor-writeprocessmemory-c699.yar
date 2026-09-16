rule TTP_XOR_WriteProcessMemory_c699 {
  strings:
    $key_c699 = { 91 eb [2] a3 c9 [2] a5 fc [2] 8b fc [2] b4 e0 }

  condition:
    any of them
}