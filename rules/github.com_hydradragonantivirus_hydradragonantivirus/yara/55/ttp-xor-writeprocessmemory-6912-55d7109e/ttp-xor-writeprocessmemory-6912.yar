rule TTP_XOR_WriteProcessMemory_6912 {
  strings:
    $key_6912 = { 3e 60 [2] 0c 42 [2] 0a 77 [2] 24 77 [2] 1b 6b }

  condition:
    any of them
}