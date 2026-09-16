rule TTP_XOR_WriteProcessMemory_29cd {
  strings:
    $key_29cd = { 7e bf [2] 4c 9d [2] 4a a8 [2] 64 a8 [2] 5b b4 }

  condition:
    any of them
}