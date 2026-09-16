rule TTP_XOR_WriteProcessMemory_2b58 {
  strings:
    $key_2b58 = { 7c 2a [2] 4e 08 [2] 48 3d [2] 66 3d [2] 59 21 }

  condition:
    any of them
}