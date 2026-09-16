rule TTP_XOR_WriteProcessMemory_46cd {
  strings:
    $key_46cd = { 11 bf [2] 23 9d [2] 25 a8 [2] 0b a8 [2] 34 b4 }

  condition:
    any of them
}