rule TTP_XOR_WriteProcessMemory_08af {
  strings:
    $key_08af = { 5f dd [2] 6d ff [2] 6b ca [2] 45 ca [2] 7a d6 }

  condition:
    any of them
}