rule TTP_XOR_WriteProcessMemory_6480 {
  strings:
    $key_6480 = { 33 f2 [2] 01 d0 [2] 07 e5 [2] 29 e5 [2] 16 f9 }

  condition:
    any of them
}