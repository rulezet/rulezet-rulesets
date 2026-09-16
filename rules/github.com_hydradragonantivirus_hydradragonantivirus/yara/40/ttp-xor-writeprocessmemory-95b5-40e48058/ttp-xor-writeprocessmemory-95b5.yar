rule TTP_XOR_WriteProcessMemory_95b5 {
  strings:
    $key_95b5 = { c2 c7 [2] f0 e5 [2] f6 d0 [2] d8 d0 [2] e7 cc }

  condition:
    any of them
}