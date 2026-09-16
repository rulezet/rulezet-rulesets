rule TTP_XOR_WriteProcessMemory_2186 {
  strings:
    $key_2186 = { 76 f4 [2] 44 d6 [2] 42 e3 [2] 6c e3 [2] 53 ff }

  condition:
    any of them
}