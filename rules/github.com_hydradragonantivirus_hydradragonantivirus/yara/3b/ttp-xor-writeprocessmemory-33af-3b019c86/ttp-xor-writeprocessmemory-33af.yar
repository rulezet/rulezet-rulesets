rule TTP_XOR_WriteProcessMemory_33af {
  strings:
    $key_33af = { 64 dd [2] 56 ff [2] 50 ca [2] 7e ca [2] 41 d6 }

  condition:
    any of them
}