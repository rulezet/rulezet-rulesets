rule TTP_XOR_WriteProcessMemory_c919 {
  strings:
    $key_c919 = { 9e 6b [2] ac 49 [2] aa 7c [2] 84 7c [2] bb 60 }

  condition:
    any of them
}