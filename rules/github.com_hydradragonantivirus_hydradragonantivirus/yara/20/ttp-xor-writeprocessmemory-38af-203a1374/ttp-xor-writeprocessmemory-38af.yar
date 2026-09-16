rule TTP_XOR_WriteProcessMemory_38af {
  strings:
    $key_38af = { 6f dd [2] 5d ff [2] 5b ca [2] 75 ca [2] 4a d6 }

  condition:
    any of them
}