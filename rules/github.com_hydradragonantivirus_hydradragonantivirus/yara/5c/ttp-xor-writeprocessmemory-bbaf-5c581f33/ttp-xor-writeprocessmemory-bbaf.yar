rule TTP_XOR_WriteProcessMemory_bbaf {
  strings:
    $key_bbaf = { ec dd [2] de ff [2] d8 ca [2] f6 ca [2] c9 d6 }

  condition:
    any of them
}