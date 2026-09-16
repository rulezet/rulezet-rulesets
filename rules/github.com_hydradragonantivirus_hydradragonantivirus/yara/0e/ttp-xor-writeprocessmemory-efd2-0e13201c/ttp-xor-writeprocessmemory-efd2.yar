rule TTP_XOR_WriteProcessMemory_efd2 {
  strings:
    $key_efd2 = { b8 a0 [2] 8a 82 [2] 8c b7 [2] a2 b7 [2] 9d ab }

  condition:
    any of them
}