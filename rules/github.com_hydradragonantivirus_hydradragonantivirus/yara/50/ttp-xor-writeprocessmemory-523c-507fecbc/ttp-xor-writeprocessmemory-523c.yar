rule TTP_XOR_WriteProcessMemory_523c {
  strings:
    $key_523c = { 05 4e [2] 37 6c [2] 31 59 [2] 1f 59 [2] 20 45 }

  condition:
    any of them
}