rule TTP_XOR_WriteProcessMemory_ecd8 {
  strings:
    $key_ecd8 = { bb aa [2] 89 88 [2] 8f bd [2] a1 bd [2] 9e a1 }

  condition:
    any of them
}