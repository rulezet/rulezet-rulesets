rule TTP_XOR_WriteProcessMemory_abaf {
  strings:
    $key_abaf = { fc dd [2] ce ff [2] c8 ca [2] e6 ca [2] d9 d6 }

  condition:
    any of them
}