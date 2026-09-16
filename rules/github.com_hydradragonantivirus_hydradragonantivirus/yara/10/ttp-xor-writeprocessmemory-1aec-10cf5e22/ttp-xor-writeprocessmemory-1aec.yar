rule TTP_XOR_WriteProcessMemory_1aec {
  strings:
    $key_1aec = { 4d 9e [2] 7f bc [2] 79 89 [2] 57 89 [2] 68 95 }

  condition:
    any of them
}