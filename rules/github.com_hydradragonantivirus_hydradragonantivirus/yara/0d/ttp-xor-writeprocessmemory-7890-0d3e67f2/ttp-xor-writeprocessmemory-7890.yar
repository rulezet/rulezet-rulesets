rule TTP_XOR_WriteProcessMemory_7890 {
  strings:
    $key_7890 = { 2f e2 [2] 1d c0 [2] 1b f5 [2] 35 f5 [2] 0a e9 }

  condition:
    any of them
}