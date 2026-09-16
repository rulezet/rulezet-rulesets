rule TTP_XOR_WriteProcessMemory_859a {
  strings:
    $key_859a = { d2 e8 [2] e0 ca [2] e6 ff [2] c8 ff [2] f7 e3 }

  condition:
    any of them
}