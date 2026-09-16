rule TTP_XOR_WriteProcessMemory_68af {
  strings:
    $key_68af = { 3f dd [2] 0d ff [2] 0b ca [2] 25 ca [2] 1a d6 }

  condition:
    any of them
}