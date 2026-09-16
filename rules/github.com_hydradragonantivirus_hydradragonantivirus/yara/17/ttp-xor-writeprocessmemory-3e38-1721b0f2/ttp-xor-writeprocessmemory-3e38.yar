rule TTP_XOR_WriteProcessMemory_3e38 {
  strings:
    $key_3e38 = { 69 4a [2] 5b 68 [2] 5d 5d [2] 73 5d [2] 4c 41 }

  condition:
    any of them
}