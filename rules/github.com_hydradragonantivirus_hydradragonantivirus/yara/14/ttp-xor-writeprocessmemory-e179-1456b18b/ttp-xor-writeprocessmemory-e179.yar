rule TTP_XOR_WriteProcessMemory_e179 {
  strings:
    $key_e179 = { b6 0b [2] 84 29 [2] 82 1c [2] ac 1c [2] 93 00 }

  condition:
    any of them
}