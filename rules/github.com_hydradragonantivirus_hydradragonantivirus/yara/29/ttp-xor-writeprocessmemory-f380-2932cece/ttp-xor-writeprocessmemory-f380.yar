rule TTP_XOR_WriteProcessMemory_f380 {
  strings:
    $key_f380 = { a4 f2 [2] 96 d0 [2] 90 e5 [2] be e5 [2] 81 f9 }

  condition:
    any of them
}