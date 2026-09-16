rule TTP_XOR_WriteProcessMemory_03cd {
  strings:
    $key_03cd = { 54 bf [2] 66 9d [2] 60 a8 [2] 4e a8 [2] 71 b4 }

  condition:
    any of them
}