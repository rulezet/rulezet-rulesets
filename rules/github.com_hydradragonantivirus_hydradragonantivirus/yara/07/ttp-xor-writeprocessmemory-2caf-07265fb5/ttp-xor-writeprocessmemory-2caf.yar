rule TTP_XOR_WriteProcessMemory_2caf {
  strings:
    $key_2caf = { 7b dd [2] 49 ff [2] 4f ca [2] 61 ca [2] 5e d6 }

  condition:
    any of them
}