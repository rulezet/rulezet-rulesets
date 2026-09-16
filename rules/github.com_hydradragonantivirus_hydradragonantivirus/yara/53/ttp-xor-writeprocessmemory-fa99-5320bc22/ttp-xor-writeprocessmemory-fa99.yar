rule TTP_XOR_WriteProcessMemory_fa99 {
  strings:
    $key_fa99 = { ad eb [2] 9f c9 [2] 99 fc [2] b7 fc [2] 88 e0 }

  condition:
    any of them
}