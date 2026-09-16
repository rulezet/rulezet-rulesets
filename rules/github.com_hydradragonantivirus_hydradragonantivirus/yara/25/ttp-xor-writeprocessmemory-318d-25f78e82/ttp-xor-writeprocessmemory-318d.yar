rule TTP_XOR_WriteProcessMemory_318d {
  strings:
    $key_318d = { 66 ff [2] 54 dd [2] 52 e8 [2] 7c e8 [2] 43 f4 }

  condition:
    any of them
}