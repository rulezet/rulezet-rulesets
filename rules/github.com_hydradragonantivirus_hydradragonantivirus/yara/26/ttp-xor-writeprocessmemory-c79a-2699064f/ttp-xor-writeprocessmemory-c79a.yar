rule TTP_XOR_WriteProcessMemory_c79a {
  strings:
    $key_c79a = { 90 e8 [2] a2 ca [2] a4 ff [2] 8a ff [2] b5 e3 }

  condition:
    any of them
}