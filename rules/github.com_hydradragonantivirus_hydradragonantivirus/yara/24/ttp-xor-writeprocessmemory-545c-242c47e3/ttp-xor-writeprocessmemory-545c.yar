rule TTP_XOR_WriteProcessMemory_545c {
  strings:
    $key_545c = { 03 2e [2] 31 0c [2] 37 39 [2] 19 39 [2] 26 25 }

  condition:
    any of them
}