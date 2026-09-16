rule TTP_XOR_WriteProcessMemory_909a {
  strings:
    $key_909a = { c7 e8 [2] f5 ca [2] f3 ff [2] dd ff [2] e2 e3 }

  condition:
    any of them
}