rule TTP_XOR_WriteProcessMemory_ee1d {
  strings:
    $key_ee1d = { b9 6f [2] 8b 4d [2] 8d 78 [2] a3 78 [2] 9c 64 }

  condition:
    any of them
}