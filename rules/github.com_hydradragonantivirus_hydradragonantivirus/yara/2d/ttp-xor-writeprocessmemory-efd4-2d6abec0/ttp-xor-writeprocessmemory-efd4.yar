rule TTP_XOR_WriteProcessMemory_efd4 {
  strings:
    $key_efd4 = { b8 a6 [2] 8a 84 [2] 8c b1 [2] a2 b1 [2] 9d ad }

  condition:
    any of them
}