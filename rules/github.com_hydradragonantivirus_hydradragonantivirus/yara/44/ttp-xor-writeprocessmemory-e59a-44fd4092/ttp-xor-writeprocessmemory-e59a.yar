rule TTP_XOR_WriteProcessMemory_e59a {
  strings:
    $key_e59a = { b2 e8 [2] 80 ca [2] 86 ff [2] a8 ff [2] 97 e3 }

  condition:
    any of them
}