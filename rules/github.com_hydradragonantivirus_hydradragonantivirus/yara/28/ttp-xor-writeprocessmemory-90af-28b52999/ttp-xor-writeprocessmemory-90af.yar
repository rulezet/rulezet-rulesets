rule TTP_XOR_WriteProcessMemory_90af {
  strings:
    $key_90af = { c7 dd [2] f5 ff [2] f3 ca [2] dd ca [2] e2 d6 }

  condition:
    any of them
}