rule TTP_XOR_WriteProcessMemory_7a86 {
  strings:
    $key_7a86 = { 2d f4 [2] 1f d6 [2] 19 e3 [2] 37 e3 [2] 08 ff }

  condition:
    any of them
}