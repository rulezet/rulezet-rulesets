rule TTP_XOR_WriteProcessMemory_f8af {
  strings:
    $key_f8af = { af dd [2] 9d ff [2] 9b ca [2] b5 ca [2] 8a d6 }

  condition:
    any of them
}