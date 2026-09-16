rule TTP_XOR_WriteProcessMemory_649a {
  strings:
    $key_649a = { 33 e8 [2] 01 ca [2] 07 ff [2] 29 ff [2] 16 e3 }

  condition:
    any of them
}