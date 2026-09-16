rule TTP_XOR_WriteProcessMemory_cf9a {
  strings:
    $key_cf9a = { 98 e8 [2] aa ca [2] ac ff [2] 82 ff [2] bd e3 }

  condition:
    any of them
}