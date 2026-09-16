rule TTP_XOR_WriteProcessMemory_0d41 {
  strings:
    $key_0d41 = { 5a 33 [2] 68 11 [2] 6e 24 [2] 40 24 [2] 7f 38 }

  condition:
    any of them
}