rule TTP_XOR_WriteProcessMemory_37af {
  strings:
    $key_37af = { 60 dd [2] 52 ff [2] 54 ca [2] 7a ca [2] 45 d6 }

  condition:
    any of them
}