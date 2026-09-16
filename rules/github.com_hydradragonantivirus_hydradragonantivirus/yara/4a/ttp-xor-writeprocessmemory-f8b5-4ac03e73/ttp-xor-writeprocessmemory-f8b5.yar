rule TTP_XOR_WriteProcessMemory_f8b5 {
  strings:
    $key_f8b5 = { af c7 [2] 9d e5 [2] 9b d0 [2] b5 d0 [2] 8a cc }

  condition:
    any of them
}