rule TTP_XOR_WriteProcessMemory_0197 {
  strings:
    $key_0197 = { 56 e5 [2] 64 c7 [2] 62 f2 [2] 4c f2 [2] 73 ee }

  condition:
    any of them
}