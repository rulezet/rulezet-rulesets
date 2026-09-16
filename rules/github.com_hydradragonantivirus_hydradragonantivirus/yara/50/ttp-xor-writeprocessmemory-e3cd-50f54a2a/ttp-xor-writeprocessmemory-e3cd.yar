rule TTP_XOR_WriteProcessMemory_e3cd {
  strings:
    $key_e3cd = { b4 bf [2] 86 9d [2] 80 a8 [2] ae a8 [2] 91 b4 }

  condition:
    any of them
}