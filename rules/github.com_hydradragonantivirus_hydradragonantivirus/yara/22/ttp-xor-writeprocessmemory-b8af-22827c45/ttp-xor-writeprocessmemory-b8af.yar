rule TTP_XOR_WriteProcessMemory_b8af {
  strings:
    $key_b8af = { ef dd [2] dd ff [2] db ca [2] f5 ca [2] ca d6 }

  condition:
    any of them
}