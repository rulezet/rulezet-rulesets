rule TTP_XOR_WriteProcessMemory_91a3 {
  strings:
    $key_91a3 = { c6 d1 [2] f4 f3 [2] f2 c6 [2] dc c6 [2] e3 da }

  condition:
    any of them
}