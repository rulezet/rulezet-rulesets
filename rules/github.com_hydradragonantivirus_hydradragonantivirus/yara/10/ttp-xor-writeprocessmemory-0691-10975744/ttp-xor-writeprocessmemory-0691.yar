rule TTP_XOR_WriteProcessMemory_0691 {
  strings:
    $key_0691 = { 51 e3 [2] 63 c1 [2] 65 f4 [2] 4b f4 [2] 74 e8 }

  condition:
    any of them
}