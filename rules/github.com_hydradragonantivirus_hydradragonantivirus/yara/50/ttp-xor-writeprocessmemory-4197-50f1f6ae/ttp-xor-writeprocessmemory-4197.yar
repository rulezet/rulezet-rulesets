rule TTP_XOR_WriteProcessMemory_4197 {
  strings:
    $key_4197 = { 16 e5 [2] 24 c7 [2] 22 f2 [2] 0c f2 [2] 33 ee }

  condition:
    any of them
}