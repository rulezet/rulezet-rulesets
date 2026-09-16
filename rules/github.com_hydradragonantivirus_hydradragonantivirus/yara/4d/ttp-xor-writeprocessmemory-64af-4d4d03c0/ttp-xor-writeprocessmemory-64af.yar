rule TTP_XOR_WriteProcessMemory_64af {
  strings:
    $key_64af = { 33 dd [2] 01 ff [2] 07 ca [2] 29 ca [2] 16 d6 }

  condition:
    any of them
}