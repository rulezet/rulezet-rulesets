rule TTP_XOR_WriteProcessMemory_e1b5 {
  strings:
    $key_e1b5 = { b6 c7 [2] 84 e5 [2] 82 d0 [2] ac d0 [2] 93 cc }

  condition:
    any of them
}