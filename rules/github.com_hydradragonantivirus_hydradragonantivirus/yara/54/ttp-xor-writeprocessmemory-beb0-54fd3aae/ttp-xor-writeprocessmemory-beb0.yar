rule TTP_XOR_WriteProcessMemory_beb0 {
  strings:
    $key_beb0 = { e9 c2 [2] db e0 [2] dd d5 [2] f3 d5 [2] cc c9 }

  condition:
    any of them
}