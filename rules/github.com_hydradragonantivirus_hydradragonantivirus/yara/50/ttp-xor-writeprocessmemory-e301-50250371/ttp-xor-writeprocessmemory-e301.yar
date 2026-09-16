rule TTP_XOR_WriteProcessMemory_e301 {
  strings:
    $key_e301 = { b4 73 [2] 86 51 [2] 80 64 [2] ae 64 [2] 91 78 }

  condition:
    any of them
}