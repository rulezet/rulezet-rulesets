rule TTP_XOR_WriteProcessMemory_7230 {
  strings:
    $key_7230 = { 25 42 [2] 17 60 [2] 11 55 [2] 3f 55 [2] 00 49 }

  condition:
    any of them
}