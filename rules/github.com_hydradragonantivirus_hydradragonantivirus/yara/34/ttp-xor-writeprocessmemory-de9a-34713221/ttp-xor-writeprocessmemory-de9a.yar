rule TTP_XOR_WriteProcessMemory_de9a {
  strings:
    $key_de9a = { 89 e8 [2] bb ca [2] bd ff [2] 93 ff [2] ac e3 }

  condition:
    any of them
}