rule TTP_XOR_WriteProcessMemory_ee94 {
  strings:
    $key_ee94 = { b9 e6 [2] 8b c4 [2] 8d f1 [2] a3 f1 [2] 9c ed }

  condition:
    any of them
}