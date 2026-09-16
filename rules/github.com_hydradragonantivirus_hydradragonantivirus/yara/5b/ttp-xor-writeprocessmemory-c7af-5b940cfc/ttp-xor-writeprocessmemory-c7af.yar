rule TTP_XOR_WriteProcessMemory_c7af {
  strings:
    $key_c7af = { 90 dd [2] a2 ff [2] a4 ca [2] 8a ca [2] b5 d6 }

  condition:
    any of them
}