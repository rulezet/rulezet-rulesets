rule TTP_XOR_WriteProcessMemory_ab82 {
  strings:
    $key_ab82 = { fc f0 [2] ce d2 [2] c8 e7 [2] e6 e7 [2] d9 fb }

  condition:
    any of them
}