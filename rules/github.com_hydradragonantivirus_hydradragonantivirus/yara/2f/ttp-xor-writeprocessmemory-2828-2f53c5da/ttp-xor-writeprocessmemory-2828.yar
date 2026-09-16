rule TTP_XOR_WriteProcessMemory_2828 {
  strings:
    $key_2828 = { 7f 5a [2] 4d 78 [2] 4b 4d [2] 65 4d [2] 5a 51 }

  condition:
    any of them
}