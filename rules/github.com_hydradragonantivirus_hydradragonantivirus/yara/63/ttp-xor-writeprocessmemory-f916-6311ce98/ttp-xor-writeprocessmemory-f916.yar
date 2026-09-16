rule TTP_XOR_WriteProcessMemory_f916 {
  strings:
    $key_f916 = { ae 64 [2] 9c 46 [2] 9a 73 [2] b4 73 [2] 8b 6f }

  condition:
    any of them
}