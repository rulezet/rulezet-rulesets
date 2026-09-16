rule TTP_XOR_WriteProcessMemory_0548 {
  strings:
    $key_0548 = { 52 3a [2] 60 18 [2] 66 2d [2] 48 2d [2] 77 31 }

  condition:
    any of them
}