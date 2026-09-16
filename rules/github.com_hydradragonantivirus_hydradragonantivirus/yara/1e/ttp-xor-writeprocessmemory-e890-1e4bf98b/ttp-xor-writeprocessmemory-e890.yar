rule TTP_XOR_WriteProcessMemory_e890 {
  strings:
    $key_e890 = { bf e2 [2] 8d c0 [2] 8b f5 [2] a5 f5 [2] 9a e9 }

  condition:
    any of them
}