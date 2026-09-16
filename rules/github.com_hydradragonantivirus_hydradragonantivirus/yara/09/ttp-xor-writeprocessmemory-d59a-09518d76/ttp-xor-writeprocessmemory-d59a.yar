rule TTP_XOR_WriteProcessMemory_d59a {
  strings:
    $key_d59a = { 82 e8 [2] b0 ca [2] b6 ff [2] 98 ff [2] a7 e3 }

  condition:
    any of them
}