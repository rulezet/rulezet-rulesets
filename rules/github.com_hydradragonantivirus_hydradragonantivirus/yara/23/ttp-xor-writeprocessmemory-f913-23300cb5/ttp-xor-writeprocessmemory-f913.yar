rule TTP_XOR_WriteProcessMemory_f913 {
  strings:
    $key_f913 = { ae 61 [2] 9c 43 [2] 9a 76 [2] b4 76 [2] 8b 6a }

  condition:
    any of them
}