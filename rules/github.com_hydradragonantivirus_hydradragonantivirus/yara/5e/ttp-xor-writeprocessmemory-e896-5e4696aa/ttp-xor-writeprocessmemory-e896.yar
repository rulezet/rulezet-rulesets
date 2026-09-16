rule TTP_XOR_WriteProcessMemory_e896 {
  strings:
    $key_e896 = { bf e4 [2] 8d c6 [2] 8b f3 [2] a5 f3 [2] 9a ef }

  condition:
    any of them
}