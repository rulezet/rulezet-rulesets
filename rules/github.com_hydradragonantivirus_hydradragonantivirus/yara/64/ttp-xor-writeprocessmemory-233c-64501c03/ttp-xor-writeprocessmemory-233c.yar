rule TTP_XOR_WriteProcessMemory_233c {
  strings:
    $key_233c = { 74 4e [2] 46 6c [2] 40 59 [2] 6e 59 [2] 51 45 }

  condition:
    any of them
}