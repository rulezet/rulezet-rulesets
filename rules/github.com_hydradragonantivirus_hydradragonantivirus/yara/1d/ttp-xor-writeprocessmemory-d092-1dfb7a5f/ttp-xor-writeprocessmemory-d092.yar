rule TTP_XOR_WriteProcessMemory_d092 {
  strings:
    $key_d092 = { 87 e0 [2] b5 c2 [2] b3 f7 [2] 9d f7 [2] a2 eb }

  condition:
    any of them
}