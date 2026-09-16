rule TTP_XOR_WriteProcessMemory_0958 {
  strings:
    $key_0958 = { 5e 2a [2] 6c 08 [2] 6a 3d [2] 44 3d [2] 7b 21 }

  condition:
    any of them
}