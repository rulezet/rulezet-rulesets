rule TTP_XOR_WriteProcessMemory_2728 {
  strings:
    $key_2728 = { 70 5a [2] 42 78 [2] 44 4d [2] 6a 4d [2] 55 51 }

  condition:
    any of them
}