rule TTP_XOR_WriteProcessMemory_d732 {
  strings:
    $key_d732 = { 80 40 [2] b2 62 [2] b4 57 [2] 9a 57 [2] a5 4b }

  condition:
    any of them
}