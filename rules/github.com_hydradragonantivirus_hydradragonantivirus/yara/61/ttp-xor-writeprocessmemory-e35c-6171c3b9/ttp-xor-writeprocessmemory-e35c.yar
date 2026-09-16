rule TTP_XOR_WriteProcessMemory_e35c {
  strings:
    $key_e35c = { b4 2e [2] 86 0c [2] 80 39 [2] ae 39 [2] 91 25 }

  condition:
    any of them
}