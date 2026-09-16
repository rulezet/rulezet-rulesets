rule TTP_XOR_WriteProcessMemory_e109 {
  strings:
    $key_e109 = { b6 7b [2] 84 59 [2] 82 6c [2] ac 6c [2] 93 70 }

  condition:
    any of them
}