rule TTP_XOR_WriteProcessMemory_658d {
  strings:
    $key_658d = { 32 ff [2] 00 dd [2] 06 e8 [2] 28 e8 [2] 17 f4 }

  condition:
    any of them
}