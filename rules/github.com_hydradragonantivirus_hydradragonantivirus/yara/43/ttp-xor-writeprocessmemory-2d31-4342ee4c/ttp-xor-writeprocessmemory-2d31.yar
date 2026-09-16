rule TTP_XOR_WriteProcessMemory_2d31 {
  strings:
    $key_2d31 = { 7a 43 [2] 48 61 [2] 4e 54 [2] 60 54 [2] 5f 48 }

  condition:
    any of them
}