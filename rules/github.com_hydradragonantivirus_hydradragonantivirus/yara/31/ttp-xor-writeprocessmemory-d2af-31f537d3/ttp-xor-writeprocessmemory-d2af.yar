rule TTP_XOR_WriteProcessMemory_d2af {
  strings:
    $key_d2af = { 85 dd [2] b7 ff [2] b1 ca [2] 9f ca [2] a0 d6 }

  condition:
    any of them
}