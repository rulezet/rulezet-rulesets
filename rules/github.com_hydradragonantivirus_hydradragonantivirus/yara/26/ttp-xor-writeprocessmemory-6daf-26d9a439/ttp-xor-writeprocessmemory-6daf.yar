rule TTP_XOR_WriteProcessMemory_6daf {
  strings:
    $key_6daf = { 3a dd [2] 08 ff [2] 0e ca [2] 20 ca [2] 1f d6 }

  condition:
    any of them
}