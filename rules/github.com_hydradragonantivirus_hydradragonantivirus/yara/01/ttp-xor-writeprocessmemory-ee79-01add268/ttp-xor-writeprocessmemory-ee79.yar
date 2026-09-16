rule TTP_XOR_WriteProcessMemory_ee79 {
  strings:
    $key_ee79 = { b9 0b [2] 8b 29 [2] 8d 1c [2] a3 1c [2] 9c 00 }

  condition:
    any of them
}