rule TTP_XOR_WriteProcessMemory_4282 {
  strings:
    $key_4282 = { 15 f0 [2] 27 d2 [2] 21 e7 [2] 0f e7 [2] 30 fb }

  condition:
    any of them
}