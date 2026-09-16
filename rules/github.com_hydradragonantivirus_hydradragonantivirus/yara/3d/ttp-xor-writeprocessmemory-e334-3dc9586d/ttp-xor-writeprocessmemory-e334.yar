rule TTP_XOR_WriteProcessMemory_e334 {
  strings:
    $key_e334 = { b4 46 [2] 86 64 [2] 80 51 [2] ae 51 [2] 91 4d }

  condition:
    any of them
}