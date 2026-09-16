rule TTP_XOR_WriteProcessMemory_da3b {
  strings:
    $key_da3b = { 8d 49 [2] bf 6b [2] b9 5e [2] 97 5e [2] a8 42 }

  condition:
    any of them
}