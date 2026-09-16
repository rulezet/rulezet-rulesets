rule TTP_XOR_WriteProcessMemory_e391 {
  strings:
    $key_e391 = { b4 e3 [2] 86 c1 [2] 80 f4 [2] ae f4 [2] 91 e8 }

  condition:
    any of them
}