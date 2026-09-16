rule TTP_XOR_WriteProcessMemory_af9a {
  strings:
    $key_af9a = { f8 e8 [2] ca ca [2] cc ff [2] e2 ff [2] dd e3 }

  condition:
    any of them
}