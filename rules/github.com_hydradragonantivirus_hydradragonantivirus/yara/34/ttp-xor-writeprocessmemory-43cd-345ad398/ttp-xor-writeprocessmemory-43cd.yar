rule TTP_XOR_WriteProcessMemory_43cd {
  strings:
    $key_43cd = { 14 bf [2] 26 9d [2] 20 a8 [2] 0e a8 [2] 31 b4 }

  condition:
    any of them
}