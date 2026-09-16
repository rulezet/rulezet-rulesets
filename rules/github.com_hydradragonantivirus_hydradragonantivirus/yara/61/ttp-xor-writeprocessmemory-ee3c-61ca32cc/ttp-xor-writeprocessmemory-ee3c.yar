rule TTP_XOR_WriteProcessMemory_ee3c {
  strings:
    $key_ee3c = { b9 4e [2] 8b 6c [2] 8d 59 [2] a3 59 [2] 9c 45 }

  condition:
    any of them
}