rule TTP_XOR_WriteProcessMemory_3087 {
  strings:
    $key_3087 = { 67 f5 [2] 55 d7 [2] 53 e2 [2] 7d e2 [2] 42 fe }

  condition:
    any of them
}