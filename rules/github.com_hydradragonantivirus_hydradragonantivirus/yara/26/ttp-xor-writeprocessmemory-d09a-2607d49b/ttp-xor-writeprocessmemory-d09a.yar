rule TTP_XOR_WriteProcessMemory_d09a {
  strings:
    $key_d09a = { 87 e8 [2] b5 ca [2] b3 ff [2] 9d ff [2] a2 e3 }

  condition:
    any of them
}