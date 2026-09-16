rule TTP_XOR_WriteProcessMemory_c49a {
  strings:
    $key_c49a = { 93 e8 [2] a1 ca [2] a7 ff [2] 89 ff [2] b6 e3 }

  condition:
    any of them
}