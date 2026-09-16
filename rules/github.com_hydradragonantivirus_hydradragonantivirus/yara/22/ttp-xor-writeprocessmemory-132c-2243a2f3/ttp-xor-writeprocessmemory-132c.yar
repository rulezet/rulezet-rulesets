rule TTP_XOR_WriteProcessMemory_132c {
  strings:
    $key_132c = { 44 5e [2] 76 7c [2] 70 49 [2] 5e 49 [2] 61 55 }

  condition:
    any of them
}