rule TTP_XOR_WriteProcessMemory_3738 {
  strings:
    $key_3738 = { 60 4a [2] 52 68 [2] 54 5d [2] 7a 5d [2] 45 41 }

  condition:
    any of them
}