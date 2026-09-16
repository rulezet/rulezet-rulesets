rule TTP_XOR_WriteProcessMemory_f4bd {
  strings:
    $key_f4bd = { a3 cf [2] 91 ed [2] 97 d8 [2] b9 d8 [2] 86 c4 }

  condition:
    any of them
}