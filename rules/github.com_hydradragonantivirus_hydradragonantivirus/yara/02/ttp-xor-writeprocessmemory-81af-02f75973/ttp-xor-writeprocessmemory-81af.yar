rule TTP_XOR_WriteProcessMemory_81af {
  strings:
    $key_81af = { d6 dd [2] e4 ff [2] e2 ca [2] cc ca [2] f3 d6 }

  condition:
    any of them
}