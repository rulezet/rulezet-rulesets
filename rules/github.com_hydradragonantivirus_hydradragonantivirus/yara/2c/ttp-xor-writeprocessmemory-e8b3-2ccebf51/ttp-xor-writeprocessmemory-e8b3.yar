rule TTP_XOR_WriteProcessMemory_e8b3 {
  strings:
    $key_e8b3 = { bf c1 [2] 8d e3 [2] 8b d6 [2] a5 d6 [2] 9a ca }

  condition:
    any of them
}