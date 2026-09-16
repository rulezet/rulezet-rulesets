rule TTP_XOR_WriteProcessMemory_ead8 {
  strings:
    $key_ead8 = { bd aa [2] 8f 88 [2] 89 bd [2] a7 bd [2] 98 a1 }

  condition:
    any of them
}