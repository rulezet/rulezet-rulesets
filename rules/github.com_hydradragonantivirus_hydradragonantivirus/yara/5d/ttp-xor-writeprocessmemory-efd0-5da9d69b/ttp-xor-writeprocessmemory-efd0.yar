rule TTP_XOR_WriteProcessMemory_efd0 {
  strings:
    $key_efd0 = { b8 a2 [2] 8a 80 [2] 8c b5 [2] a2 b5 [2] 9d a9 }

  condition:
    any of them
}