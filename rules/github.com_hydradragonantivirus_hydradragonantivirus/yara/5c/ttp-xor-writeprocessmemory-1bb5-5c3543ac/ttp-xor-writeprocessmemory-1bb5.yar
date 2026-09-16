rule TTP_XOR_WriteProcessMemory_1bb5 {
  strings:
    $key_1bb5 = { 4c c7 [2] 7e e5 [2] 78 d0 [2] 56 d0 [2] 69 cc }

  condition:
    any of them
}