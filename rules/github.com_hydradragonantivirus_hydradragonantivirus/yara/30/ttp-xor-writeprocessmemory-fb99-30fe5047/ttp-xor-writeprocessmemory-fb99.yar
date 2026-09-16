rule TTP_XOR_WriteProcessMemory_fb99 {
  strings:
    $key_fb99 = { ac eb [2] 9e c9 [2] 98 fc [2] b6 fc [2] 89 e0 }

  condition:
    any of them
}