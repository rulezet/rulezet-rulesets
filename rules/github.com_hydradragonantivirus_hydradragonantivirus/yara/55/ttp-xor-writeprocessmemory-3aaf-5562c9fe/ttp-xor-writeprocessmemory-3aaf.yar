rule TTP_XOR_WriteProcessMemory_3aaf {
  strings:
    $key_3aaf = { 6d dd [2] 5f ff [2] 59 ca [2] 77 ca [2] 48 d6 }

  condition:
    any of them
}