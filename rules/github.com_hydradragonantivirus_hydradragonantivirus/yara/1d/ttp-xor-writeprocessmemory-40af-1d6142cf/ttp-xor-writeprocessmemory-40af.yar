rule TTP_XOR_WriteProcessMemory_40af {
  strings:
    $key_40af = { 17 dd [2] 25 ff [2] 23 ca [2] 0d ca [2] 32 d6 }

  condition:
    any of them
}