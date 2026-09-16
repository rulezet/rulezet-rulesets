rule TTP_XOR_WriteProcessMemory_d1af {
  strings:
    $key_d1af = { 86 dd [2] b4 ff [2] b2 ca [2] 9c ca [2] a3 d6 }

  condition:
    any of them
}