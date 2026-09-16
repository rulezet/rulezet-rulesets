rule TTP_XOR_WriteProcessMemory_eaec {
  strings:
    $key_eaec = { bd 9e [2] 8f bc [2] 89 89 [2] a7 89 [2] 98 95 }

  condition:
    any of them
}