rule TTP_XOR_WriteProcessMemory_0daf {
  strings:
    $key_0daf = { 5a dd [2] 68 ff [2] 6e ca [2] 40 ca [2] 7f d6 }

  condition:
    any of them
}