rule TTP_XOR_WriteProcessMemory_4daf {
  strings:
    $key_4daf = { 1a dd [2] 28 ff [2] 2e ca [2] 00 ca [2] 3f d6 }

  condition:
    any of them
}