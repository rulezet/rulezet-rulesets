rule TTP_XOR_WriteProcessMemory_5ac5 {
  strings:
    $key_5ac5 = { 0d b7 [2] 3f 95 [2] 39 a0 [2] 17 a0 [2] 28 bc }

  condition:
    any of them
}