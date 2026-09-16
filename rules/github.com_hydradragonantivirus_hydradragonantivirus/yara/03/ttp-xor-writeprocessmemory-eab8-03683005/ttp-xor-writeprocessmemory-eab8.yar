rule TTP_XOR_WriteProcessMemory_eab8 {
  strings:
    $key_eab8 = { bd ca [2] 8f e8 [2] 89 dd [2] a7 dd [2] 98 c1 }

  condition:
    any of them
}