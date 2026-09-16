rule TTP_XOR_WriteProcessMemory_2aaf {
  strings:
    $key_2aaf = { 7d dd [2] 4f ff [2] 49 ca [2] 67 ca [2] 58 d6 }

  condition:
    any of them
}