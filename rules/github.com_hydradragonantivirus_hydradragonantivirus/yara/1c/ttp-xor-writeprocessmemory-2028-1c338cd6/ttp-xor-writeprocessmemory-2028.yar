rule TTP_XOR_WriteProcessMemory_2028 {
  strings:
    $key_2028 = { 77 5a [2] 45 78 [2] 43 4d [2] 6d 4d [2] 52 51 }

  condition:
    any of them
}