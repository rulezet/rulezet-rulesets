rule TTP_XOR_WriteProcessMemory_4bc5 {
  strings:
    $key_4bc5 = { 1c b7 [2] 2e 95 [2] 28 a0 [2] 06 a0 [2] 39 bc }

  condition:
    any of them
}