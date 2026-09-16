rule TTP_XOR_WriteProcessMemory_2932 {
  strings:
    $key_2932 = { 7e 40 [2] 4c 62 [2] 4a 57 [2] 64 57 [2] 5b 4b }

  condition:
    any of them
}