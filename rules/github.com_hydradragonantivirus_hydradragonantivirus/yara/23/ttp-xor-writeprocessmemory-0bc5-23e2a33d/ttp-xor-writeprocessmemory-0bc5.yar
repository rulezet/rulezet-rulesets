rule TTP_XOR_WriteProcessMemory_0bc5 {
  strings:
    $key_0bc5 = { 5c b7 [2] 6e 95 [2] 68 a0 [2] 46 a0 [2] 79 bc }

  condition:
    any of them
}