rule TTP_XOR_WriteProcessMemory_0593 {
  strings:
    $key_0593 = { 52 e1 [2] 60 c3 [2] 66 f6 [2] 48 f6 [2] 77 ea }

  condition:
    any of them
}