rule TTP_XOR_WriteProcessMemory_e84d {
  strings:
    $key_e84d = { bf 3f [2] 8d 1d [2] 8b 28 [2] a5 28 [2] 9a 34 }

  condition:
    any of them
}