rule TTP_XOR_WriteProcessMemory_eff4 {
  strings:
    $key_eff4 = { b8 86 [2] 8a a4 [2] 8c 91 [2] a2 91 [2] 9d 8d }

  condition:
    any of them
}