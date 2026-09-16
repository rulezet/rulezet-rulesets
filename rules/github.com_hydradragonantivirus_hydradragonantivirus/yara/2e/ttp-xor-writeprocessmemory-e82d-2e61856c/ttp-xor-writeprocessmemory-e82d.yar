rule TTP_XOR_WriteProcessMemory_e82d {
  strings:
    $key_e82d = { bf 5f [2] 8d 7d [2] 8b 48 [2] a5 48 [2] 9a 54 }

  condition:
    any of them
}