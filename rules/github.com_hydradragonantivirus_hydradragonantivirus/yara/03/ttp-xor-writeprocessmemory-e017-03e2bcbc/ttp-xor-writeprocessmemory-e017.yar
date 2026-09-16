rule TTP_XOR_WriteProcessMemory_e017 {
  strings:
    $key_e017 = { b7 65 [2] 85 47 [2] 83 72 [2] ad 72 [2] 92 6e }

  condition:
    any of them
}