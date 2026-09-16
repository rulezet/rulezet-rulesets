rule TTP_XOR_WriteProcessMemory_0191 {
  strings:
    $key_0191 = { 56 e3 [2] 64 c1 [2] 62 f4 [2] 4c f4 [2] 73 e8 }

  condition:
    any of them
}