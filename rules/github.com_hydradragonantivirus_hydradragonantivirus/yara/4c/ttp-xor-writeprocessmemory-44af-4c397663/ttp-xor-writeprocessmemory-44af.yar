rule TTP_XOR_WriteProcessMemory_44af {
  strings:
    $key_44af = { 13 dd [2] 21 ff [2] 27 ca [2] 09 ca [2] 36 d6 }

  condition:
    any of them
}