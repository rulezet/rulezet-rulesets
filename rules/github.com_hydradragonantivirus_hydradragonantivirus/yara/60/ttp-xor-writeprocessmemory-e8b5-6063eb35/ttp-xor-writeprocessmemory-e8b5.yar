rule TTP_XOR_WriteProcessMemory_e8b5 {
  strings:
    $key_e8b5 = { bf c7 [2] 8d e5 [2] 8b d0 [2] a5 d0 [2] 9a cc }

  condition:
    any of them
}