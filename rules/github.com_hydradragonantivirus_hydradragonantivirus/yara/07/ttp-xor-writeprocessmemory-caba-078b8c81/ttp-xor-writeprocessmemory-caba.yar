rule TTP_XOR_WriteProcessMemory_caba {
  strings:
    $key_caba = { 9d c8 [2] af ea [2] a9 df [2] 87 df [2] b8 c3 }

  condition:
    any of them
}