rule TTP_XOR_WriteProcessMemory_ab81 {
  strings:
    $key_ab81 = { fc f3 [2] ce d1 [2] c8 e4 [2] e6 e4 [2] d9 f8 }

  condition:
    any of them
}