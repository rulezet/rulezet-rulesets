rule TTP_XOR_WriteProcessMemory_22b5 {
  strings:
    $key_22b5 = { 75 c7 [2] 47 e5 [2] 41 d0 [2] 6f d0 [2] 50 cc }

  condition:
    any of them
}