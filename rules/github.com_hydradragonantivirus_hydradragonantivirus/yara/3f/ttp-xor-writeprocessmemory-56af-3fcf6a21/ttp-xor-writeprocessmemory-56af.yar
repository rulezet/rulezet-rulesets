rule TTP_XOR_WriteProcessMemory_56af {
  strings:
    $key_56af = { 01 dd [2] 33 ff [2] 35 ca [2] 1b ca [2] 24 d6 }

  condition:
    any of them
}