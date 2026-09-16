rule TTP_XOR_WriteProcessMemory_c181 {
  strings:
    $key_c181 = { 96 f3 [2] a4 d1 [2] a2 e4 [2] 8c e4 [2] b3 f8 }

  condition:
    any of them
}