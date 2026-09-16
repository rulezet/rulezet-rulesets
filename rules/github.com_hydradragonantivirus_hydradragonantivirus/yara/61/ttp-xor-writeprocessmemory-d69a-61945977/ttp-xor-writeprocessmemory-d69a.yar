rule TTP_XOR_WriteProcessMemory_d69a {
  strings:
    $key_d69a = { 81 e8 [2] b3 ca [2] b5 ff [2] 9b ff [2] a4 e3 }

  condition:
    any of them
}