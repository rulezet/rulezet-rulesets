rule TTP_XOR_WriteProcessMemory_72b5 {
  strings:
    $key_72b5 = { 25 c7 [2] 17 e5 [2] 11 d0 [2] 3f d0 [2] 00 cc }

  condition:
    any of them
}