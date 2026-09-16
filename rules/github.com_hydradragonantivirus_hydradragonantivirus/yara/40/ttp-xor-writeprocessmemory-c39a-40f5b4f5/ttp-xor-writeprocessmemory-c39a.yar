rule TTP_XOR_WriteProcessMemory_c39a {
  strings:
    $key_c39a = { 94 e8 [2] a6 ca [2] a0 ff [2] 8e ff [2] b1 e3 }

  condition:
    any of them
}