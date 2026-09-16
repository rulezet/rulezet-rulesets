rule TTP_XOR_WriteProcessMemory_84af {
  strings:
    $key_84af = { d3 dd [2] e1 ff [2] e7 ca [2] c9 ca [2] f6 d6 }

  condition:
    any of them
}