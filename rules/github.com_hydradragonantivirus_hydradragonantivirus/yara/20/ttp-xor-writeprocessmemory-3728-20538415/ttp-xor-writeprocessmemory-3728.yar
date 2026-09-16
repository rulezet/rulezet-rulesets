rule TTP_XOR_WriteProcessMemory_3728 {
  strings:
    $key_3728 = { 60 5a [2] 52 78 [2] 54 4d [2] 7a 4d [2] 45 51 }

  condition:
    any of them
}