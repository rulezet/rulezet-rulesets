rule TTP_XOR_WriteProcessMemory_72af {
  strings:
    $key_72af = { 25 dd [2] 17 ff [2] 11 ca [2] 3f ca [2] 00 d6 }

  condition:
    any of them
}