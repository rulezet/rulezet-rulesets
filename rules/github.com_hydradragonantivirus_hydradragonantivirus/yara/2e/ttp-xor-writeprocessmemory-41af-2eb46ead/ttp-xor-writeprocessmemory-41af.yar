rule TTP_XOR_WriteProcessMemory_41af {
  strings:
    $key_41af = { 16 dd [2] 24 ff [2] 22 ca [2] 0c ca [2] 33 d6 }

  condition:
    any of them
}