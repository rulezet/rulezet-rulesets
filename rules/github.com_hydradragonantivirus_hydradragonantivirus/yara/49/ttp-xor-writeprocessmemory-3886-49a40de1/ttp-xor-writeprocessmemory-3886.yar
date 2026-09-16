rule TTP_XOR_WriteProcessMemory_3886 {
  strings:
    $key_3886 = { 6f f4 [2] 5d d6 [2] 5b e3 [2] 75 e3 [2] 4a ff }

  condition:
    any of them
}