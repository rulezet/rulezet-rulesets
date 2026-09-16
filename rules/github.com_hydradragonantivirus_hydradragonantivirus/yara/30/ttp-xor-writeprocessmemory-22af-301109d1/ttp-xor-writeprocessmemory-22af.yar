rule TTP_XOR_WriteProcessMemory_22af {
  strings:
    $key_22af = { 75 dd [2] 47 ff [2] 41 ca [2] 6f ca [2] 50 d6 }

  condition:
    any of them
}