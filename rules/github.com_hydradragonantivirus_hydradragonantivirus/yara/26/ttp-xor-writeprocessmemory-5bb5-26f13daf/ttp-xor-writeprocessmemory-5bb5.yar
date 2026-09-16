rule TTP_XOR_WriteProcessMemory_5bb5 {
  strings:
    $key_5bb5 = { 0c c7 [2] 3e e5 [2] 38 d0 [2] 16 d0 [2] 29 cc }

  condition:
    any of them
}