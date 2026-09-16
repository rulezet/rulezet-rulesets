rule TTP_XOR_WriteProcessMemory_ead3 {
  strings:
    $key_ead3 = { bd a1 [2] 8f 83 [2] 89 b6 [2] a7 b6 [2] 98 aa }

  condition:
    any of them
}