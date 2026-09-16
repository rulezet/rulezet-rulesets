rule TTP_XOR_WriteProcessMemory_d724 {
  strings:
    $key_d724 = { 80 56 [2] b2 74 [2] b4 41 [2] 9a 41 [2] a5 5d }

  condition:
    any of them
}