rule TTP_XOR_WriteProcessMemory_fcdc {
  strings:
    $key_fcdc = { ab ae [2] 99 8c [2] 9f b9 [2] b1 b9 [2] 8e a5 }

  condition:
    any of them
}