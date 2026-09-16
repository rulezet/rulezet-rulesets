rule TTP_XOR_WriteProcessMemory_a78d {
  strings:
    $key_a78d = { f0 ff [2] c2 dd [2] c4 e8 [2] ea e8 [2] d5 f4 }

  condition:
    any of them
}