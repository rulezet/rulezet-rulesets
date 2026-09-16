rule TTP_XOR_WriteProcessMemory_5bc5 {
  strings:
    $key_5bc5 = { 0c b7 [2] 3e 95 [2] 38 a0 [2] 16 a0 [2] 29 bc }

  condition:
    any of them
}