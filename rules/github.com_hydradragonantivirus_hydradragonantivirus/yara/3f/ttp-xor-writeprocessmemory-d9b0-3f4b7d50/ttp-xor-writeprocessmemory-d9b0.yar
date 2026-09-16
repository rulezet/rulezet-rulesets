rule TTP_XOR_WriteProcessMemory_d9b0 {
  strings:
    $key_d9b0 = { 8e c2 [2] bc e0 [2] ba d5 [2] 94 d5 [2] ab c9 }

  condition:
    any of them
}