rule TTP_XOR_WriteProcessMemory_3baf {
  strings:
    $key_3baf = { 6c dd [2] 5e ff [2] 58 ca [2] 76 ca [2] 49 d6 }

  condition:
    any of them
}