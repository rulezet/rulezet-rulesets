rule TTP_XOR_WriteProcessMemory_eac4 {
  strings:
    $key_eac4 = { bd b6 [2] 8f 94 [2] 89 a1 [2] a7 a1 [2] 98 bd }

  condition:
    any of them
}