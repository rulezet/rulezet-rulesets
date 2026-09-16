rule TTP_XOR_WriteProcessMemory_e344 {
  strings:
    $key_e344 = { b4 36 [2] 86 14 [2] 80 21 [2] ae 21 [2] 91 3d }

  condition:
    any of them
}