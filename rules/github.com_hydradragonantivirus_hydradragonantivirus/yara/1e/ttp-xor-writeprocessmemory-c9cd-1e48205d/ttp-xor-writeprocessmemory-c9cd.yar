rule TTP_XOR_WriteProcessMemory_c9cd {
  strings:
    $key_c9cd = { 9e bf [2] ac 9d [2] aa a8 [2] 84 a8 [2] bb b4 }

  condition:
    any of them
}