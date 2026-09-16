rule TTP_XOR_WriteProcessMemory_eec0 {
  strings:
    $key_eec0 = { b9 b2 [2] 8b 90 [2] 8d a5 [2] a3 a5 [2] 9c b9 }

  condition:
    any of them
}