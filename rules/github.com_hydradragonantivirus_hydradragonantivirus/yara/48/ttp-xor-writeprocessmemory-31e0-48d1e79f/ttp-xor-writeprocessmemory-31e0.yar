rule TTP_XOR_WriteProcessMemory_31e0 {
  strings:
    $key_31e0 = { 66 92 [2] 54 b0 [2] 52 85 [2] 7c 85 [2] 43 99 }

  condition:
    any of them
}