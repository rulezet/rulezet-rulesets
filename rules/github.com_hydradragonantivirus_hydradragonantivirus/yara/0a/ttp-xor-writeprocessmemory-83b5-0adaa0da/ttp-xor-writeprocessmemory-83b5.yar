rule TTP_XOR_WriteProcessMemory_83b5 {
  strings:
    $key_83b5 = { d4 c7 [2] e6 e5 [2] e0 d0 [2] ce d0 [2] f1 cc }

  condition:
    any of them
}