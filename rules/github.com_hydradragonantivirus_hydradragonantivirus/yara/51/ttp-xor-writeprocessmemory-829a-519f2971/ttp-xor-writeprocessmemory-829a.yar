rule TTP_XOR_WriteProcessMemory_829a {
  strings:
    $key_829a = { d5 e8 [2] e7 ca [2] e1 ff [2] cf ff [2] f0 e3 }

  condition:
    any of them
}