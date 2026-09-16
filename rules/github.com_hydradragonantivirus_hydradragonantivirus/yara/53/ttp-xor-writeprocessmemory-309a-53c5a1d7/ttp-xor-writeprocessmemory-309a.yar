rule TTP_XOR_WriteProcessMemory_309a {
  strings:
    $key_309a = { 67 e8 [2] 55 ca [2] 53 ff [2] 7d ff [2] 42 e3 }

  condition:
    any of them
}