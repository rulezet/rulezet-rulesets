rule TTP_XOR_WriteProcessMemory_0186 {
  strings:
    $key_0186 = { 56 f4 [2] 64 d6 [2] 62 e3 [2] 4c e3 [2] 73 ff }

  condition:
    any of them
}