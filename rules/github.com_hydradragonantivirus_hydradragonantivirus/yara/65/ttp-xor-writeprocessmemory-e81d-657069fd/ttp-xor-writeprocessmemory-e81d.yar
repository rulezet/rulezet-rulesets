rule TTP_XOR_WriteProcessMemory_e81d {
  strings:
    $key_e81d = { bf 6f [2] 8d 4d [2] 8b 78 [2] a5 78 [2] 9a 64 }

  condition:
    any of them
}