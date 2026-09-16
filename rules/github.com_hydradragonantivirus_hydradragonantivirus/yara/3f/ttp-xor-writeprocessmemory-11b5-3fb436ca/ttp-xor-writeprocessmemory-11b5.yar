rule TTP_XOR_WriteProcessMemory_11b5 {
  strings:
    $key_11b5 = { 46 c7 [2] 74 e5 [2] 72 d0 [2] 5c d0 [2] 63 cc }

  condition:
    any of them
}