rule TTP_XOR_WriteProcessMemory_fc14 {
  strings:
    $key_fc14 = { ab 66 [2] 99 44 [2] 9f 71 [2] b1 71 [2] 8e 6d }

  condition:
    any of them
}