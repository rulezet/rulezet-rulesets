rule TTP_XOR_WriteProcessMemory_1baf {
  strings:
    $key_1baf = { 4c dd [2] 7e ff [2] 78 ca [2] 56 ca [2] 69 d6 }

  condition:
    any of them
}