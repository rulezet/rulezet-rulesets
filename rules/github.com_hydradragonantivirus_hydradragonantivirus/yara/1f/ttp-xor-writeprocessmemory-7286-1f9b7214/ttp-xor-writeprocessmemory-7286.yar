rule TTP_XOR_WriteProcessMemory_7286 {
  strings:
    $key_7286 = { 25 f4 [2] 17 d6 [2] 11 e3 [2] 3f e3 [2] 00 ff }

  condition:
    any of them
}