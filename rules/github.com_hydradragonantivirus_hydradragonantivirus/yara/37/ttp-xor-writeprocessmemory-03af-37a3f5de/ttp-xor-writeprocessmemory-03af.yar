rule TTP_XOR_WriteProcessMemory_03af {
  strings:
    $key_03af = { 54 dd [2] 66 ff [2] 60 ca [2] 4e ca [2] 71 d6 }

  condition:
    any of them
}