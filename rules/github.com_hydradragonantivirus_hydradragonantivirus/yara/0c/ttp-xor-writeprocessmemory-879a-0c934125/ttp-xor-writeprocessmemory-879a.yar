rule TTP_XOR_WriteProcessMemory_879a {
  strings:
    $key_879a = { d0 e8 [2] e2 ca [2] e4 ff [2] ca ff [2] f5 e3 }

  condition:
    any of them
}