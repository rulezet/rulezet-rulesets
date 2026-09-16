rule TTP_XOR_WriteProcessMemory_3bb5 {
  strings:
    $key_3bb5 = { 6c c7 [2] 5e e5 [2] 58 d0 [2] 76 d0 [2] 49 cc }

  condition:
    any of them
}