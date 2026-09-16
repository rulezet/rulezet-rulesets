rule TTP_XOR_WriteProcessMemory_0d77 {
  strings:
    $key_0d77 = { 5a 05 [2] 68 27 [2] 6e 12 [2] 40 12 [2] 7f 0e }

  condition:
    any of them
}