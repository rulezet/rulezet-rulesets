rule TTP_XOR_WriteProcessMemory_e3d9 {
  strings:
    $key_e3d9 = { b4 ab [2] 86 89 [2] 80 bc [2] ae bc [2] 91 a0 }

  condition:
    any of them
}