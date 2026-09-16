rule TTP_XOR_WriteProcessMemory_f931 {
  strings:
    $key_f931 = { ae 43 [2] 9c 61 [2] 9a 54 [2] b4 54 [2] 8b 48 }

  condition:
    any of them
}