rule TTP_XOR_WriteProcessMemory_096d {
  strings:
    $key_096d = { 5e 1f [2] 6c 3d [2] 6a 08 [2] 44 08 [2] 7b 14 }

  condition:
    any of them
}