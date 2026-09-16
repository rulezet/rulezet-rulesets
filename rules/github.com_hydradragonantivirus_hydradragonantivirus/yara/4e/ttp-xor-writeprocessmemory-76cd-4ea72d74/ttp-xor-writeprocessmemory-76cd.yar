rule TTP_XOR_WriteProcessMemory_76cd {
  strings:
    $key_76cd = { 21 bf [2] 13 9d [2] 15 a8 [2] 3b a8 [2] 04 b4 }

  condition:
    any of them
}