rule TTP_XOR_WriteProcessMemory_fa85 {
  strings:
    $key_fa85 = { ad f7 [2] 9f d5 [2] 99 e0 [2] b7 e0 [2] 88 fc }

  condition:
    any of them
}