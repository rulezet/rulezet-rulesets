rule TTP_XOR_WriteProcessMemory_05d5 {
  strings:
    $key_05d5 = { 52 a7 [2] 60 85 [2] 66 b0 [2] 48 b0 [2] 77 ac }

  condition:
    any of them
}