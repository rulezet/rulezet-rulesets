rule TTP_XOR_WriteProcessMemory_f941 {
  strings:
    $key_f941 = { ae 33 [2] 9c 11 [2] 9a 24 [2] b4 24 [2] 8b 38 }

  condition:
    any of them
}