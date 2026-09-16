rule TTP_XOR_WriteProcessMemory_ccb5 {
  strings:
    $key_ccb5 = { 9b c7 [2] a9 e5 [2] af d0 [2] 81 d0 [2] be cc }

  condition:
    any of them
}