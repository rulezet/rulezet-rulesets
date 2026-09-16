rule TTP_XOR_WriteProcessMemory_daee {
  strings:
    $key_daee = { 8d 9c [2] bf be [2] b9 8b [2] 97 8b [2] a8 97 }

  condition:
    any of them
}