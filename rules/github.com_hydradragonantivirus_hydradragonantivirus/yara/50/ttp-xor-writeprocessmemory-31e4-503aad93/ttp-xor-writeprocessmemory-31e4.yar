rule TTP_XOR_WriteProcessMemory_31e4 {
  strings:
    $key_31e4 = { 66 96 [2] 54 b4 [2] 52 81 [2] 7c 81 [2] 43 9d }

  condition:
    any of them
}