rule TTP_XOR_WriteProcessMemory_6d67 {
  strings:
    $key_6d67 = { 3a 15 [2] 08 37 [2] 0e 02 [2] 20 02 [2] 1f 1e }

  condition:
    any of them
}