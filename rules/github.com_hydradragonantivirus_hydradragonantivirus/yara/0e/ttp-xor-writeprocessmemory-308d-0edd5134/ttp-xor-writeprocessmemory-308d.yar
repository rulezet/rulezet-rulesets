rule TTP_XOR_WriteProcessMemory_308d {
  strings:
    $key_308d = { 67 ff [2] 55 dd [2] 53 e8 [2] 7d e8 [2] 42 f4 }

  condition:
    any of them
}