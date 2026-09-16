rule TTP_XOR_WriteProcessMemory_0bc3 {
  strings:
    $key_0bc3 = { 5c b1 [2] 6e 93 [2] 68 a6 [2] 46 a6 [2] 79 ba }

  condition:
    any of them
}