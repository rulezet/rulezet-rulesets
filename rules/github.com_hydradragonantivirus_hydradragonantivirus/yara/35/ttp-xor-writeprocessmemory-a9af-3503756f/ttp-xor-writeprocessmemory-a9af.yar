rule TTP_XOR_WriteProcessMemory_a9af {
  strings:
    $key_a9af = { fe dd [2] cc ff [2] ca ca [2] e4 ca [2] db d6 }

  condition:
    any of them
}