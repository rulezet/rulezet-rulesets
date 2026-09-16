rule TTP_XOR_WriteProcessMemory_13af {
  strings:
    $key_13af = { 44 dd [2] 76 ff [2] 70 ca [2] 5e ca [2] 61 d6 }

  condition:
    any of them
}