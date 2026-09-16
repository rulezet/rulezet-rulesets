rule TTP_XOR_WriteProcessMemory_bda2 {
  strings:
    $key_bda2 = { ea d0 [2] d8 f2 [2] de c7 [2] f0 c7 [2] cf db }

  condition:
    any of them
}