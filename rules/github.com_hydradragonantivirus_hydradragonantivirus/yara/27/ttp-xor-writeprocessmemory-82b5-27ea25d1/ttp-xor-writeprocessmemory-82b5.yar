rule TTP_XOR_WriteProcessMemory_82b5 {
  strings:
    $key_82b5 = { d5 c7 [2] e7 e5 [2] e1 d0 [2] cf d0 [2] f0 cc }

  condition:
    any of them
}