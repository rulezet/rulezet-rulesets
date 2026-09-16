rule TTP_XOR_WriteProcessMemory_ca99 {
  strings:
    $key_ca99 = { 9d eb [2] af c9 [2] a9 fc [2] 87 fc [2] b8 e0 }

  condition:
    any of them
}