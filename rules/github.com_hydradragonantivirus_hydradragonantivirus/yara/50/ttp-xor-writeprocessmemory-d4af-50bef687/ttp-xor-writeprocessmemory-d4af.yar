rule TTP_XOR_WriteProcessMemory_d4af {
  strings:
    $key_d4af = { 83 dd [2] b1 ff [2] b7 ca [2] 99 ca [2] a6 d6 }

  condition:
    any of them
}