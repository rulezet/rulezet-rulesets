rule TTP_XOR_WriteProcessMemory_37b5 {
  strings:
    $key_37b5 = { 60 c7 [2] 52 e5 [2] 54 d0 [2] 7a d0 [2] 45 cc }

  condition:
    any of them
}