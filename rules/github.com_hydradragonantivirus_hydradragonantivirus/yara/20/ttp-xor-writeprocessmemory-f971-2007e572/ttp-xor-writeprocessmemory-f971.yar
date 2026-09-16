rule TTP_XOR_WriteProcessMemory_f971 {
  strings:
    $key_f971 = { ae 03 [2] 9c 21 [2] 9a 14 [2] b4 14 [2] 8b 08 }

  condition:
    any of them
}