rule TTP_XOR_WriteProcessMemory_d39a {
  strings:
    $key_d39a = { 84 e8 [2] b6 ca [2] b0 ff [2] 9e ff [2] a1 e3 }

  condition:
    any of them
}