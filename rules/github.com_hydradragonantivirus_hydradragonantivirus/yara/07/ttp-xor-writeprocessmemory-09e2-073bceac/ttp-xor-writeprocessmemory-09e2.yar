rule TTP_XOR_WriteProcessMemory_09e2 {
  strings:
    $key_09e2 = { 5e 90 [2] 6c b2 [2] 6a 87 [2] 44 87 [2] 7b 9b }

  condition:
    any of them
}