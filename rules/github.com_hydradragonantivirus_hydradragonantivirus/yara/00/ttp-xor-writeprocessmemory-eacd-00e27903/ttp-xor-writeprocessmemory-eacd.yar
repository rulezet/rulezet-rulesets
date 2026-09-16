rule TTP_XOR_WriteProcessMemory_eacd {
  strings:
    $key_eacd = { bd bf [2] 8f 9d [2] 89 a8 [2] a7 a8 [2] 98 b4 }

  condition:
    any of them
}