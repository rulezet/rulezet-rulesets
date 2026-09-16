rule TTP_XOR_WriteProcessMemory_2fd5 {
  strings:
    $key_2fd5 = { 78 a7 [2] 4a 85 [2] 4c b0 [2] 62 b0 [2] 5d ac }

  condition:
    any of them
}