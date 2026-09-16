rule TTP_XOR_WriteProcessMemory_e85d {
  strings:
    $key_e85d = { bf 2f [2] 8d 0d [2] 8b 38 [2] a5 38 [2] 9a 24 }

  condition:
    any of them
}