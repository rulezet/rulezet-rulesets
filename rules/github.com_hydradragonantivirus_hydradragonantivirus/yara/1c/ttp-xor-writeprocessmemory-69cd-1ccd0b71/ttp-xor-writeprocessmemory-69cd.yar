rule TTP_XOR_WriteProcessMemory_69cd {
  strings:
    $key_69cd = { 3e bf [2] 0c 9d [2] 0a a8 [2] 24 a8 [2] 1b b4 }

  condition:
    any of them
}