rule TTP_XOR_WriteProcessMemory_e314 {
  strings:
    $key_e314 = { b4 66 [2] 86 44 [2] 80 71 [2] ae 71 [2] 91 6d }

  condition:
    any of them
}