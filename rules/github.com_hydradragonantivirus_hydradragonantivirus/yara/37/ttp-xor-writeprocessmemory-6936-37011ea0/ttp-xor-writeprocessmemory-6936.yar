rule TTP_XOR_WriteProcessMemory_6936 {
  strings:
    $key_6936 = { 3e 44 [2] 0c 66 [2] 0a 53 [2] 24 53 [2] 1b 4f }

  condition:
    any of them
}