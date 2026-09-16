rule TTP_XOR_WriteProcessMemory_e134 {
  strings:
    $key_e134 = { b6 46 [2] 84 64 [2] 82 51 [2] ac 51 [2] 93 4d }

  condition:
    any of them
}