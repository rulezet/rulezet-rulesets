rule TTP_XOR_WriteProcessMemory_d143 {
  strings:
    $key_d143 = { 86 31 [2] b4 13 [2] b2 26 [2] 9c 26 [2] a3 3a }

  condition:
    any of them
}