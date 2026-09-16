rule TTP_XOR_WriteProcessMemory_f985 {
  strings:
    $key_f985 = { ae f7 [2] 9c d5 [2] 9a e0 [2] b4 e0 [2] 8b fc }

  condition:
    any of them
}