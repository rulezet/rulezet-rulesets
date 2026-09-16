rule TTP_XOR_WriteProcessMemory_2848 {
  strings:
    $key_2848 = { 7f 3a [2] 4d 18 [2] 4b 2d [2] 65 2d [2] 5a 31 }

  condition:
    any of them
}