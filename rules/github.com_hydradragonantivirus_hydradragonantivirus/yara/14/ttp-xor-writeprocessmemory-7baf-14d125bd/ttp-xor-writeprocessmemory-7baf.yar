rule TTP_XOR_WriteProcessMemory_7baf {
  strings:
    $key_7baf = { 2c dd [2] 1e ff [2] 18 ca [2] 36 ca [2] 09 d6 }

  condition:
    any of them
}