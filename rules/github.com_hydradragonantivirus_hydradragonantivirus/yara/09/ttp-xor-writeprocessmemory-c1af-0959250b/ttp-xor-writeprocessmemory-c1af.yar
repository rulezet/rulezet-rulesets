rule TTP_XOR_WriteProcessMemory_c1af {
  strings:
    $key_c1af = { 96 dd [2] a4 ff [2] a2 ca [2] 8c ca [2] b3 d6 }

  condition:
    any of them
}