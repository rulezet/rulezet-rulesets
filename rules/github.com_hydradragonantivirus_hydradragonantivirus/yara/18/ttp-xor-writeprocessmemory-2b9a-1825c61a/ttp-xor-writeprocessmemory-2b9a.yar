rule TTP_XOR_WriteProcessMemory_2b9a {
  strings:
    $key_2b9a = { 7c e8 [2] 4e ca [2] 48 ff [2] 66 ff [2] 59 e3 }

  condition:
    any of them
}