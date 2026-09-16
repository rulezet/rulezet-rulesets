rule TTP_XOR_WriteProcessMemory_7caf {
  strings:
    $key_7caf = { 2b dd [2] 19 ff [2] 1f ca [2] 31 ca [2] 0e d6 }

  condition:
    any of them
}