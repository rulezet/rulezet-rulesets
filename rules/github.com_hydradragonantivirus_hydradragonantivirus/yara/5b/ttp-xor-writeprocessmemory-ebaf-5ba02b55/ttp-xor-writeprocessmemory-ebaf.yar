rule TTP_XOR_WriteProcessMemory_ebaf {
  strings:
    $key_ebaf = { bc dd [2] 8e ff [2] 88 ca [2] a6 ca [2] 99 d6 }

  condition:
    any of them
}