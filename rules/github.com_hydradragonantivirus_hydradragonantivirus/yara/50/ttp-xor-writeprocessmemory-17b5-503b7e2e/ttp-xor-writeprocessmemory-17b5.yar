rule TTP_XOR_WriteProcessMemory_17b5 {
  strings:
    $key_17b5 = { 40 c7 [2] 72 e5 [2] 74 d0 [2] 5a d0 [2] 65 cc }

  condition:
    any of them
}