rule TTP_XOR_WriteProcessMemory_abc1 {
  strings:
    $key_abc1 = { fc b3 [2] ce 91 [2] c8 a4 [2] e6 a4 [2] d9 b8 }

  condition:
    any of them
}