rule TTP_XOR_WriteProcessMemory_aad9 {
  strings:
    $key_aad9 = { fd ab [2] cf 89 [2] c9 bc [2] e7 bc [2] d8 a0 }

  condition:
    any of them
}