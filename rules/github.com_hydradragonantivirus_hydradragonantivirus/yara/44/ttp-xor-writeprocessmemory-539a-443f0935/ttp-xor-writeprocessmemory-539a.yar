rule TTP_XOR_WriteProcessMemory_539a {
  strings:
    $key_539a = { 04 e8 [2] 36 ca [2] 30 ff [2] 1e ff [2] 21 e3 }

  condition:
    any of them
}