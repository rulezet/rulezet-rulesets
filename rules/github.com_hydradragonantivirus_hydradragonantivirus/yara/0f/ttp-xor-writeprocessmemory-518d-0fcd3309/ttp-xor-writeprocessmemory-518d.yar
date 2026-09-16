rule TTP_XOR_WriteProcessMemory_518d {
  strings:
    $key_518d = { 06 ff [2] 34 dd [2] 32 e8 [2] 1c e8 [2] 23 f4 }

  condition:
    any of them
}