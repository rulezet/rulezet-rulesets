rule TTP_XOR_WriteProcessMemory_3187 {
  strings:
    $key_3187 = { 66 f5 [2] 54 d7 [2] 52 e2 [2] 7c e2 [2] 43 fe }

  condition:
    any of them
}