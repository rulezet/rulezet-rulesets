rule TTP_XOR_WriteProcessMemory_fe9a {
  strings:
    $key_fe9a = { a9 e8 [2] 9b ca [2] 9d ff [2] b3 ff [2] 8c e3 }

  condition:
    any of them
}