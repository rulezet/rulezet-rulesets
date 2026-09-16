rule TTP_XOR_WriteProcessMemory_e80d {
  strings:
    $key_e80d = { bf 7f [2] 8d 5d [2] 8b 68 [2] a5 68 [2] 9a 74 }

  condition:
    any of them
}