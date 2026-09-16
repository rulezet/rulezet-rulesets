rule TTP_XOR_WriteProcessMemory_538d {
  strings:
    $key_538d = { 04 ff [2] 36 dd [2] 30 e8 [2] 1e e8 [2] 21 f4 }

  condition:
    any of them
}