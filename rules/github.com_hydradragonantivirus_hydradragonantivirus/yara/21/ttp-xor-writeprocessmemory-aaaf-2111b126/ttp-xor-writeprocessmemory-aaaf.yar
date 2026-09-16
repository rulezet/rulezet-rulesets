rule TTP_XOR_WriteProcessMemory_aaaf {
  strings:
    $key_aaaf = { fd dd [2] cf ff [2] c9 ca [2] e7 ca [2] d8 d6 }

  condition:
    any of them
}