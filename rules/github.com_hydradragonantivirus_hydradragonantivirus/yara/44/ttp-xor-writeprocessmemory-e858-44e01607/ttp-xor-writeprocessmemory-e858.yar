rule TTP_XOR_WriteProcessMemory_e858 {
  strings:
    $key_e858 = { bf 2a [2] 8d 08 [2] 8b 3d [2] a5 3d [2] 9a 21 }

  condition:
    any of them
}