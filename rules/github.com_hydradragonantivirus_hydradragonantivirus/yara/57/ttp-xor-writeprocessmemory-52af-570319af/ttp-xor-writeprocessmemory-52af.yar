rule TTP_XOR_WriteProcessMemory_52af {
  strings:
    $key_52af = { 05 dd [2] 37 ff [2] 31 ca [2] 1f ca [2] 20 d6 }

  condition:
    any of them
}