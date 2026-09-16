rule TTP_XOR_WriteProcessMemory_d79a {
  strings:
    $key_d79a = { 80 e8 [2] b2 ca [2] b4 ff [2] 9a ff [2] a5 e3 }

  condition:
    any of them
}