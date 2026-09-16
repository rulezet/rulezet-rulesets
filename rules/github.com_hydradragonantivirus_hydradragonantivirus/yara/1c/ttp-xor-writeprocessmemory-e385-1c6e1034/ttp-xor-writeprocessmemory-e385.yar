rule TTP_XOR_WriteProcessMemory_e385 {
  strings:
    $key_e385 = { b4 f7 [2] 86 d5 [2] 80 e0 [2] ae e0 [2] 91 fc }

  condition:
    any of them
}