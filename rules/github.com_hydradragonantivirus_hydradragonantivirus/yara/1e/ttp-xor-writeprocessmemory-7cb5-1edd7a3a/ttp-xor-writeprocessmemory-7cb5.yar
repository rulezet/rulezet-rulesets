rule TTP_XOR_WriteProcessMemory_7cb5 {
  strings:
    $key_7cb5 = { 2b c7 [2] 19 e5 [2] 1f d0 [2] 31 d0 [2] 0e cc }

  condition:
    any of them
}