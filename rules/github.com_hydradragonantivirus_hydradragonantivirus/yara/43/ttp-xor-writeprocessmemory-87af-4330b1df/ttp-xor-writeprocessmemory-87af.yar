rule TTP_XOR_WriteProcessMemory_87af {
  strings:
    $key_87af = { d0 dd [2] e2 ff [2] e4 ca [2] ca ca [2] f5 d6 }

  condition:
    any of them
}