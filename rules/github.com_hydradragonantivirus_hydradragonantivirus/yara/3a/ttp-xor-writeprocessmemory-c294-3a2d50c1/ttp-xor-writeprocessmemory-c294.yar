rule TTP_XOR_WriteProcessMemory_c294 {
  strings:
    $key_c294 = { 95 e6 [2] a7 c4 [2] a1 f1 [2] 8f f1 [2] b0 ed }

  condition:
    any of them
}