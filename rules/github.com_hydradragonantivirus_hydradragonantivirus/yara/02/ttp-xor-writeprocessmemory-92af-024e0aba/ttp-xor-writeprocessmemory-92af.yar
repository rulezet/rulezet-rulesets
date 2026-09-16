rule TTP_XOR_WriteProcessMemory_92af {
  strings:
    $key_92af = { c5 dd [2] f7 ff [2] f1 ca [2] df ca [2] e0 d6 }

  condition:
    any of them
}