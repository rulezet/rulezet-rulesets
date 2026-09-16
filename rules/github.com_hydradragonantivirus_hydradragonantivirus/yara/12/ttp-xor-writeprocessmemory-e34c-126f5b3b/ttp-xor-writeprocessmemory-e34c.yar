rule TTP_XOR_WriteProcessMemory_e34c {
  strings:
    $key_e34c = { b4 3e [2] 86 1c [2] 80 29 [2] ae 29 [2] 91 35 }

  condition:
    any of them
}