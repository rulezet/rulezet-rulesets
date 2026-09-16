rule TTP_XOR_WriteProcessMemory_76b5 {
  strings:
    $key_76b5 = { 21 c7 [2] 13 e5 [2] 15 d0 [2] 3b d0 [2] 04 cc }

  condition:
    any of them
}