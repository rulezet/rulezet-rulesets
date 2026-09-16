rule TTP_XOR_WriteProcessMemory_e80c {
  strings:
    $key_e80c = { bf 7e [2] 8d 5c [2] 8b 69 [2] a5 69 [2] 9a 75 }

  condition:
    any of them
}