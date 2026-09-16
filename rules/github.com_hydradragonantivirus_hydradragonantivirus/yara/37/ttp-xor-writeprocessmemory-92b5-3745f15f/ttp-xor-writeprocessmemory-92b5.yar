rule TTP_XOR_WriteProcessMemory_92b5 {
  strings:
    $key_92b5 = { c5 c7 [2] f7 e5 [2] f1 d0 [2] df d0 [2] e0 cc }

  condition:
    any of them
}