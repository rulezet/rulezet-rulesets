rule TTP_XOR_WriteProcessMemory_f943 {
  strings:
    $key_f943 = { ae 31 [2] 9c 13 [2] 9a 26 [2] b4 26 [2] 8b 3a }

  condition:
    any of them
}