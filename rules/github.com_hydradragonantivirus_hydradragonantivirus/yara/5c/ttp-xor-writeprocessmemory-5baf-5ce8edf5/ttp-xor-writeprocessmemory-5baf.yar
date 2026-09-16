rule TTP_XOR_WriteProcessMemory_5baf {
  strings:
    $key_5baf = { 0c dd [2] 3e ff [2] 38 ca [2] 16 ca [2] 29 d6 }

  condition:
    any of them
}