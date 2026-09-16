rule TTP_XOR_WriteProcessMemory_f86d {
  strings:
    $key_f86d = { af 1f [2] 9d 3d [2] 9b 08 [2] b5 08 [2] 8a 14 }

  condition:
    any of them
}