rule TTP_XOR_WriteProcessMemory_46af {
  strings:
    $key_46af = { 11 dd [2] 23 ff [2] 25 ca [2] 0b ca [2] 34 d6 }

  condition:
    any of them
}