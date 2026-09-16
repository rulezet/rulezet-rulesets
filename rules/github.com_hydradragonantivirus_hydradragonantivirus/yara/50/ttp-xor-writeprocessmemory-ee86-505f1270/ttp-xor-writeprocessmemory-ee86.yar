rule TTP_XOR_WriteProcessMemory_ee86 {
  strings:
    $key_ee86 = { b9 f4 [2] 8b d6 [2] 8d e3 [2] a3 e3 [2] 9c ff }

  condition:
    any of them
}