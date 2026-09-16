rule TTP_XOR_WriteProcessMemory_e82c {
  strings:
    $key_e82c = { bf 5e [2] 8d 7c [2] 8b 49 [2] a5 49 [2] 9a 55 }

  condition:
    any of them
}