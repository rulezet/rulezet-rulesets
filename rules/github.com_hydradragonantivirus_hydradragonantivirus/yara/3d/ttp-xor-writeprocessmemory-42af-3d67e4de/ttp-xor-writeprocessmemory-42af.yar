rule TTP_XOR_WriteProcessMemory_42af {
  strings:
    $key_42af = { 15 dd [2] 27 ff [2] 21 ca [2] 0f ca [2] 30 d6 }

  condition:
    any of them
}