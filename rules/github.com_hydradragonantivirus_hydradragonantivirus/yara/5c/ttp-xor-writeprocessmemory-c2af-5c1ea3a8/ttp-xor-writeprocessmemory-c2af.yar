rule TTP_XOR_WriteProcessMemory_c2af {
  strings:
    $key_c2af = { 95 dd [2] a7 ff [2] a1 ca [2] 8f ca [2] b0 d6 }

  condition:
    any of them
}