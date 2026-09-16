rule TTP_XOR_WriteProcessMemory_eeef {
  strings:
    $key_eeef = { b9 9d [2] 8b bf [2] 8d 8a [2] a3 8a [2] 9c 96 }

  condition:
    any of them
}