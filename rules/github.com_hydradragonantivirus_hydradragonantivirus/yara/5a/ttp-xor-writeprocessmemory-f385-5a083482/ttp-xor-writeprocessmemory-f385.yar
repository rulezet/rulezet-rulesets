rule TTP_XOR_WriteProcessMemory_f385 {
  strings:
    $key_f385 = { a4 f7 [2] 96 d5 [2] 90 e0 [2] be e0 [2] 81 fc }

  condition:
    any of them
}