rule TTP_XOR_WriteProcessMemory_149a {
  strings:
    $key_149a = { 43 e8 [2] 71 ca [2] 77 ff [2] 59 ff [2] 66 e3 }

  condition:
    any of them
}