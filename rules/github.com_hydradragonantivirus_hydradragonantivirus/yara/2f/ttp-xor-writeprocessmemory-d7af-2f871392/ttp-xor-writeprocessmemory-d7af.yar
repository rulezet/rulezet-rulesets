rule TTP_XOR_WriteProcessMemory_d7af {
  strings:
    $key_d7af = { 80 dd [2] b2 ff [2] b4 ca [2] 9a ca [2] a5 d6 }

  condition:
    any of them
}