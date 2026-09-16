rule TTP_XOR_WriteProcessMemory_83af {
  strings:
    $key_83af = { d4 dd [2] e6 ff [2] e0 ca [2] ce ca [2] f1 d6 }

  condition:
    any of them
}