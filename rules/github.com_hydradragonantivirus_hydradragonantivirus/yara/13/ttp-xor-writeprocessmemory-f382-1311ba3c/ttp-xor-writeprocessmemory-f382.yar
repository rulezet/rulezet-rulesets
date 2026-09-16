rule TTP_XOR_WriteProcessMemory_f382 {
  strings:
    $key_f382 = { a4 f0 [2] 96 d2 [2] 90 e7 [2] be e7 [2] 81 fb }

  condition:
    any of them
}