rule TTP_XOR_WriteProcessMemory_2baf {
  strings:
    $key_2baf = { 7c dd [2] 4e ff [2] 48 ca [2] 66 ca [2] 59 d6 }

  condition:
    any of them
}