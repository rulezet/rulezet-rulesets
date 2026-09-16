rule TTP_XOR_WriteProcessMemory_eadc {
  strings:
    $key_eadc = { bd ae [2] 8f 8c [2] 89 b9 [2] a7 b9 [2] 98 a5 }

  condition:
    any of them
}