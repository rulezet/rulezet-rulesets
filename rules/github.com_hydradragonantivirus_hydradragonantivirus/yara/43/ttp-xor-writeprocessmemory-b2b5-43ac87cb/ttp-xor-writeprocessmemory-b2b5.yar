rule TTP_XOR_WriteProcessMemory_b2b5 {
  strings:
    $key_b2b5 = { e5 c7 [2] d7 e5 [2] d1 d0 [2] ff d0 [2] c0 cc }

  condition:
    any of them
}