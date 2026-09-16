rule TTP_XOR_WriteProcessMemory_ca93 {
  strings:
    $key_ca93 = { 9d e1 [2] af c3 [2] a9 f6 [2] 87 f6 [2] b8 ea }

  condition:
    any of them
}