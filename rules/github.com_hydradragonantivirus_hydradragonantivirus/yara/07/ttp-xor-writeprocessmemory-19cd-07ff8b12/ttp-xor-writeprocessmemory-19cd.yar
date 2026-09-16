rule TTP_XOR_WriteProcessMemory_19cd {
  strings:
    $key_19cd = { 4e bf [2] 7c 9d [2] 7a a8 [2] 54 a8 [2] 6b b4 }

  condition:
    any of them
}