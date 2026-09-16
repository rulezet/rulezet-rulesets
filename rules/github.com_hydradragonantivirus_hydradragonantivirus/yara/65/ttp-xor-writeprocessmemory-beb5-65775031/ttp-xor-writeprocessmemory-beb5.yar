rule TTP_XOR_WriteProcessMemory_beb5 {
  strings:
    $key_beb5 = { e9 c7 [2] db e5 [2] dd d0 [2] f3 d0 [2] cc cc }

  condition:
    any of them
}