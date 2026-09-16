rule TTP_XOR_WriteProcessMemory_c09a {
  strings:
    $key_c09a = { 97 e8 [2] a5 ca [2] a3 ff [2] 8d ff [2] b2 e3 }

  condition:
    any of them
}