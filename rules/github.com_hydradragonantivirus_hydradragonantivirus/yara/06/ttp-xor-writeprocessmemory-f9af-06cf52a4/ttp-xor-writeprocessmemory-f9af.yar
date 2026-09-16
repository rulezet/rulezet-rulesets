rule TTP_XOR_WriteProcessMemory_f9af {
  strings:
    $key_f9af = { ae dd [2] 9c ff [2] 9a ca [2] b4 ca [2] 8b d6 }

  condition:
    any of them
}