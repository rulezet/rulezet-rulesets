rule TTP_XOR_WriteProcessMemory_44b5 {
  strings:
    $key_44b5 = { 13 c7 [2] 21 e5 [2] 27 d0 [2] 09 d0 [2] 36 cc }

  condition:
    any of them
}