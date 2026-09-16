rule TTP_XOR_WriteProcessMemory_3818 {
  strings:
    $key_3818 = { 6f 6a [2] 5d 48 [2] 5b 7d [2] 75 7d [2] 4a 61 }

  condition:
    any of them
}