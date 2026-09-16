rule TTP_XOR_WriteProcessMemory_939a {
  strings:
    $key_939a = { c4 e8 [2] f6 ca [2] f0 ff [2] de ff [2] e1 e3 }

  condition:
    any of them
}