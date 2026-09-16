rule TTP_XOR_WriteProcessMemory_3128 {
  strings:
    $key_3128 = { 66 5a [2] 54 78 [2] 52 4d [2] 7c 4d [2] 43 51 }

  condition:
    any of them
}