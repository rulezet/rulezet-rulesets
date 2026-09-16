rule TTP_XOR_WriteProcessMemory_31e6 {
  strings:
    $key_31e6 = { 66 94 [2] 54 b6 [2] 52 83 [2] 7c 83 [2] 43 9f }

  condition:
    any of them
}