rule TTP_XOR_WriteProcessMemory_d6af {
  strings:
    $key_d6af = { 81 dd [2] b3 ff [2] b5 ca [2] 9b ca [2] a4 d6 }

  condition:
    any of them
}