rule TTP_XOR_WriteProcessMemory_4191 {
  strings:
    $key_4191 = { 16 e3 [2] 24 c1 [2] 22 f4 [2] 0c f4 [2] 33 e8 }

  condition:
    any of them
}