rule TTP_XOR_WriteProcessMemory_59cd {
  strings:
    $key_59cd = { 0e bf [2] 3c 9d [2] 3a a8 [2] 14 a8 [2] 2b b4 }

  condition:
    any of them
}