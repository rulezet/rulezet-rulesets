rule TTP_XOR_WriteProcessMemory_c6b5 {
  strings:
    $key_c6b5 = { 91 c7 [2] a3 e5 [2] a5 d0 [2] 8b d0 [2] b4 cc }

  condition:
    any of them
}