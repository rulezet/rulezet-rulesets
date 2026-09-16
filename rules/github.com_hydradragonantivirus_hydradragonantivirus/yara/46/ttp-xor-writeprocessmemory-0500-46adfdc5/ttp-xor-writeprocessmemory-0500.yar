rule TTP_XOR_WriteProcessMemory_0500 {
  strings:
    $key_0500 = { 52 72 [2] 60 50 [2] 66 65 [2] 48 65 [2] 77 79 }

  condition:
    any of them
}