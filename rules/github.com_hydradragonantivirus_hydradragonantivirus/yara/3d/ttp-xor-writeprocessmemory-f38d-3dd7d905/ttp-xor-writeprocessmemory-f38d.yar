rule TTP_XOR_WriteProcessMemory_f38d {
  strings:
    $key_f38d = { a4 ff [2] 96 dd [2] 90 e8 [2] be e8 [2] 81 f4 }

  condition:
    any of them
}