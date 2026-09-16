rule TTP_XOR_WriteProcessMemory_e89f {
  strings:
    $key_e89f = { bf ed [2] 8d cf [2] 8b fa [2] a5 fa [2] 9a e6 }

  condition:
    any of them
}