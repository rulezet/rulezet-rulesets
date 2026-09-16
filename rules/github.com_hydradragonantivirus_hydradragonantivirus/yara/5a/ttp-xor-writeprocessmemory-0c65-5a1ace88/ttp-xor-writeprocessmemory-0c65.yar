rule TTP_XOR_WriteProcessMemory_0c65 {
  strings:
    $key_0c65 = { 5b 17 [2] 69 35 [2] 6f 00 [2] 41 00 [2] 7e 1c }

  condition:
    any of them
}