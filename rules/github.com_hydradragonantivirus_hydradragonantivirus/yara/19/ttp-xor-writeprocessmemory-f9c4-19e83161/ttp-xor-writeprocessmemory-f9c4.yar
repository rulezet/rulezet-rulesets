rule TTP_XOR_WriteProcessMemory_f9c4 {
  strings:
    $key_f9c4 = { ae b6 [2] 9c 94 [2] 9a a1 [2] b4 a1 [2] 8b bd }

  condition:
    any of them
}