rule TTP_XOR_WriteProcessMemory_eaaf {
  strings:
    $key_eaaf = { bd dd [2] 8f ff [2] 89 ca [2] a7 ca [2] 98 d6 }

  condition:
    any of them
}