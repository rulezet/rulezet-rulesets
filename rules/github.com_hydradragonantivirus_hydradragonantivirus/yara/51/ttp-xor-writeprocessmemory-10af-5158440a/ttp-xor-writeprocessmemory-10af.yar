rule TTP_XOR_WriteProcessMemory_10af {
  strings:
    $key_10af = { 47 dd [2] 75 ff [2] 73 ca [2] 5d ca [2] 62 d6 }

  condition:
    any of them
}