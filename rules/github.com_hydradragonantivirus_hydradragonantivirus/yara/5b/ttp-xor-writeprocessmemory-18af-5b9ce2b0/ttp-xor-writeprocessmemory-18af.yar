rule TTP_XOR_WriteProcessMemory_18af {
  strings:
    $key_18af = { 4f dd [2] 7d ff [2] 7b ca [2] 55 ca [2] 6a d6 }

  condition:
    any of them
}