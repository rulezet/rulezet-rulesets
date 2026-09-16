rule TTP_XOR_WriteProcessMemory_37a3 {
  strings:
    $key_37a3 = { 60 d1 [2] 52 f3 [2] 54 c6 [2] 7a c6 [2] 45 da }

  condition:
    any of them
}