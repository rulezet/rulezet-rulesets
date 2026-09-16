rule TTP_XOR_WriteProcessMemory_f29f {
  strings:
    $key_f29f = { a5 ed [2] 97 cf [2] 91 fa [2] bf fa [2] 80 e6 }

  condition:
    any of them
}