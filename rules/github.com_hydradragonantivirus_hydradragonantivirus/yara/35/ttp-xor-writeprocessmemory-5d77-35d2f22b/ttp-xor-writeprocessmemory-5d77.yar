rule TTP_XOR_WriteProcessMemory_5d77 {
  strings:
    $key_5d77 = { 0a 05 [2] 38 27 [2] 3e 12 [2] 10 12 [2] 2f 0e }

  condition:
    any of them
}