rule TTP_XOR_WriteProcessMemory_d19a {
  strings:
    $key_d19a = { 86 e8 [2] b4 ca [2] b2 ff [2] 9c ff [2] a3 e3 }

  condition:
    any of them
}