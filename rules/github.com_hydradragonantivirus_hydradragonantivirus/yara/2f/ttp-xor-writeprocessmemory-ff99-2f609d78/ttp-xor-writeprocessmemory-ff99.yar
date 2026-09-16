rule TTP_XOR_WriteProcessMemory_ff99 {
  strings:
    $key_ff99 = { a8 eb [2] 9a c9 [2] 9c fc [2] b2 fc [2] 8d e0 }

  condition:
    any of them
}