rule TTP_XOR_WriteProcessMemory_d093 {
  strings:
    $key_d093 = { 87 e1 [2] b5 c3 [2] b3 f6 [2] 9d f6 [2] a2 ea }

  condition:
    any of them
}