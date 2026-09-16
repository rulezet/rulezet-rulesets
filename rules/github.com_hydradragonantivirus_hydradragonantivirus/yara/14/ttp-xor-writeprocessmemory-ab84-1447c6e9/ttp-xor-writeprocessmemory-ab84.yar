rule TTP_XOR_WriteProcessMemory_ab84 {
  strings:
    $key_ab84 = { fc f6 [2] ce d4 [2] c8 e1 [2] e6 e1 [2] d9 fd }

  condition:
    any of them
}