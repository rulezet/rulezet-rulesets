rule TTP_XOR_WriteProcessMemory_db85 {
  strings:
    $key_db85 = { 8c f7 [2] be d5 [2] b8 e0 [2] 96 e0 [2] a9 fc }

  condition:
    any of them
}