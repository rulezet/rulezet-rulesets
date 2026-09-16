rule TTP_XOR_WriteProcessMemory_beaf {
  strings:
    $key_beaf = { e9 dd [2] db ff [2] dd ca [2] f3 ca [2] cc d6 }

  condition:
    any of them
}