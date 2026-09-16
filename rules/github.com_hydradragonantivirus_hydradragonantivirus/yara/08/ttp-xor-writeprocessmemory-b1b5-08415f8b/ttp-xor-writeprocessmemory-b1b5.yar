rule TTP_XOR_WriteProcessMemory_b1b5 {
  strings:
    $key_b1b5 = { e6 c7 [2] d4 e5 [2] d2 d0 [2] fc d0 [2] c3 cc }

  condition:
    any of them
}