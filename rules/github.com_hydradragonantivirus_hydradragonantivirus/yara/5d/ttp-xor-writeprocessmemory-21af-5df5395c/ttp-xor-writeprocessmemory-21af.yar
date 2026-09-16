rule TTP_XOR_WriteProcessMemory_21af {
  strings:
    $key_21af = { 76 dd [2] 44 ff [2] 42 ca [2] 6c ca [2] 53 d6 }

  condition:
    any of them
}