rule TTP_XOR_WriteProcessMemory_8aaf {
  strings:
    $key_8aaf = { dd dd [2] ef ff [2] e9 ca [2] c7 ca [2] f8 d6 }

  condition:
    any of them
}