rule TTP_XOR_WriteProcessMemory_0540 {
  strings:
    $key_0540 = { 52 32 [2] 60 10 [2] 66 25 [2] 48 25 [2] 77 39 }

  condition:
    any of them
}