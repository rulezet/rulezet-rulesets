rule TTP_XOR_WriteProcessMemory_0517 {
  strings:
    $key_0517 = { 52 65 [2] 60 47 [2] 66 72 [2] 48 72 [2] 77 6e }

  condition:
    any of them
}