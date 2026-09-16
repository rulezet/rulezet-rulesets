rule TTP_XOR_WriteProcessMemory_3393 {
  strings:
    $key_3393 = { 64 e1 [2] 56 c3 [2] 50 f6 [2] 7e f6 [2] 41 ea }

  condition:
    any of them
}