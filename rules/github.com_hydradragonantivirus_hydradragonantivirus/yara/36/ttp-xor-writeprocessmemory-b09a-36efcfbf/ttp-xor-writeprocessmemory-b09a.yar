rule TTP_XOR_WriteProcessMemory_b09a {
  strings:
    $key_b09a = { e7 e8 [2] d5 ca [2] d3 ff [2] fd ff [2] c2 e3 }

  condition:
    any of them
}