rule TTP_XOR_WriteProcessMemory_ffd1 {
  strings:
    $key_ffd1 = { a8 a3 [2] 9a 81 [2] 9c b4 [2] b2 b4 [2] 8d a8 }

  condition:
    any of them
}