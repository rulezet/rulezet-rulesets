rule TTP_XOR_WriteProcessMemory_0286 {
  strings:
    $key_0286 = { 55 f4 [2] 67 d6 [2] 61 e3 [2] 4f e3 [2] 70 ff }

  condition:
    any of them
}