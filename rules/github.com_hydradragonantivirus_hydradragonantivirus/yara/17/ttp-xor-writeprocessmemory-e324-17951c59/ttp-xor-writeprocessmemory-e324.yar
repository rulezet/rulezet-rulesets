rule TTP_XOR_WriteProcessMemory_e324 {
  strings:
    $key_e324 = { b4 56 [2] 86 74 [2] 80 41 [2] ae 41 [2] 91 5d }

  condition:
    any of them
}