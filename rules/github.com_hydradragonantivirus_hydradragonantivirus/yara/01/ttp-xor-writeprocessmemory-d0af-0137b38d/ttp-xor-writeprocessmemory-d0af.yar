rule TTP_XOR_WriteProcessMemory_d0af {
  strings:
    $key_d0af = { 87 dd [2] b5 ff [2] b3 ca [2] 9d ca [2] a2 d6 }

  condition:
    any of them
}