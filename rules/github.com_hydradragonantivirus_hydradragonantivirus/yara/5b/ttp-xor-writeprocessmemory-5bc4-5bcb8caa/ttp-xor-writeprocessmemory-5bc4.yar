rule TTP_XOR_WriteProcessMemory_5bc4 {
  strings:
    $key_5bc4 = { 0c b6 [2] 3e 94 [2] 38 a1 [2] 16 a1 [2] 29 bd }

  condition:
    any of them
}