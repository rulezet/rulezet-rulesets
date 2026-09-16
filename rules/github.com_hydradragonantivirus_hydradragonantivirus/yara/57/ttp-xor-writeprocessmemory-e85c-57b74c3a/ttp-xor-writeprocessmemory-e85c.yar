rule TTP_XOR_WriteProcessMemory_e85c {
  strings:
    $key_e85c = { bf 2e [2] 8d 0c [2] 8b 39 [2] a5 39 [2] 9a 25 }

  condition:
    any of them
}