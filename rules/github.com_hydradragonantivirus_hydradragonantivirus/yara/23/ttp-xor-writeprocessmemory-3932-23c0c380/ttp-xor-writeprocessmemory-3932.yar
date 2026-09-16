rule TTP_XOR_WriteProcessMemory_3932 {
  strings:
    $key_3932 = { 6e 40 [2] 5c 62 [2] 5a 57 [2] 74 57 [2] 4b 4b }

  condition:
    any of them
}