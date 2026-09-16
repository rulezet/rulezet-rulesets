rule TTP_XOR_WriteProcessMemory_f904 {
  strings:
    $key_f904 = { ae 76 [2] 9c 54 [2] 9a 61 [2] b4 61 [2] 8b 7d }

  condition:
    any of them
}