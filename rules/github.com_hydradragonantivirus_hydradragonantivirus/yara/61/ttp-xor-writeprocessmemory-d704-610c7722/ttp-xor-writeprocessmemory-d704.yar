rule TTP_XOR_WriteProcessMemory_d704 {
  strings:
    $key_d704 = { 80 76 [2] b2 54 [2] b4 61 [2] 9a 61 [2] a5 7d }

  condition:
    any of them
}