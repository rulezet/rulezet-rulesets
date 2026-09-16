rule TTP_XOR_WriteProcessMemory_769a {
  strings:
    $key_769a = { 21 e8 [2] 13 ca [2] 15 ff [2] 3b ff [2] 04 e3 }

  condition:
    any of them
}