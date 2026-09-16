rule TTP_XOR_WriteProcessMemory_409a {
  strings:
    $key_409a = { 17 e8 [2] 25 ca [2] 23 ff [2] 0d ff [2] 32 e3 }

  condition:
    any of them
}