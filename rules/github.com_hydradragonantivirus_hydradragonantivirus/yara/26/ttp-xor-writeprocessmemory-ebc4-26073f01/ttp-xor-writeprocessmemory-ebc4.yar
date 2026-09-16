rule TTP_XOR_WriteProcessMemory_ebc4 {
  strings:
    $key_ebc4 = { bc b6 [2] 8e 94 [2] 88 a1 [2] a6 a1 [2] 99 bd }

  condition:
    any of them
}