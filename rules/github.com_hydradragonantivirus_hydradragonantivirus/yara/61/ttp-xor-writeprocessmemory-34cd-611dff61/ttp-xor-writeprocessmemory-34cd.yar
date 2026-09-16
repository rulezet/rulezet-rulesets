rule TTP_XOR_WriteProcessMemory_34cd {
  strings:
    $key_34cd = { 63 bf [2] 51 9d [2] 57 a8 [2] 79 a8 [2] 46 b4 }

  condition:
    any of them
}