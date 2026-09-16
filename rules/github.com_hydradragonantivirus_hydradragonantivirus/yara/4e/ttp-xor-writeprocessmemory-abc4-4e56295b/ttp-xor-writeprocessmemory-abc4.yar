rule TTP_XOR_WriteProcessMemory_abc4 {
  strings:
    $key_abc4 = { fc b6 [2] ce 94 [2] c8 a1 [2] e6 a1 [2] d9 bd }

  condition:
    any of them
}