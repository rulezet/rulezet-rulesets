rule TTP_XOR_WriteProcessMemory_3d99 {
  strings:
    $key_3d99 = { 6a eb [2] 58 c9 [2] 5e fc [2] 70 fc [2] 4f e0 }

  condition:
    any of them
}