rule TTP_XOR_WriteProcessMemory_0baf {
  strings:
    $key_0baf = { 5c dd [2] 6e ff [2] 68 ca [2] 46 ca [2] 79 d6 }

  condition:
    any of them
}