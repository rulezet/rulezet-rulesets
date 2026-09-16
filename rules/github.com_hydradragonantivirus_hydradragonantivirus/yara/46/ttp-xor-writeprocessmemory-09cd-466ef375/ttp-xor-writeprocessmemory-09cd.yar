rule TTP_XOR_WriteProcessMemory_09cd {
  strings:
    $key_09cd = { 5e bf [2] 6c 9d [2] 6a a8 [2] 44 a8 [2] 7b b4 }

  condition:
    any of them
}