rule TTP_XOR_WriteProcessMemory_0506 {
  strings:
    $key_0506 = { 52 74 [2] 60 56 [2] 66 63 [2] 48 63 [2] 77 7f }

  condition:
    any of them
}