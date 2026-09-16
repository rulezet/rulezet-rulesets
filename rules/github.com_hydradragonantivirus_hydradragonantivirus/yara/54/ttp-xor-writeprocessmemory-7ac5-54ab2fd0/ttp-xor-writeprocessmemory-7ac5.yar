rule TTP_XOR_WriteProcessMemory_7ac5 {
  strings:
    $key_7ac5 = { 2d b7 [2] 1f 95 [2] 19 a0 [2] 37 a0 [2] 08 bc }

  condition:
    any of them
}