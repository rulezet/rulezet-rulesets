rule TTP_XOR_WriteProcessMemory_1daf {
  strings:
    $key_1daf = { 4a dd [2] 78 ff [2] 7e ca [2] 50 ca [2] 6f d6 }

  condition:
    any of them
}