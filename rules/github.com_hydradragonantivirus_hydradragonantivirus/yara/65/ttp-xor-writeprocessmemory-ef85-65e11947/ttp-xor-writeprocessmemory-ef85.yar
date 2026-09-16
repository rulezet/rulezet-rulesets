rule TTP_XOR_WriteProcessMemory_ef85 {
  strings:
    $key_ef85 = { b8 f7 [2] 8a d5 [2] 8c e0 [2] a2 e0 [2] 9d fc }

  condition:
    any of them
}