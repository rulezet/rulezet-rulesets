rule TTP_XOR_WriteProcessMemory_159a {
  strings:
    $key_159a = { 42 e8 [2] 70 ca [2] 76 ff [2] 58 ff [2] 67 e3 }

  condition:
    any of them
}