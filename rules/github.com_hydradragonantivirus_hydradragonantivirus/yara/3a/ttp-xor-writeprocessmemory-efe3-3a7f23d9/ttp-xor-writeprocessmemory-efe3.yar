rule TTP_XOR_WriteProcessMemory_efe3 {
  strings:
    $key_efe3 = { b8 91 [2] 8a b3 [2] 8c 86 [2] a2 86 [2] 9d 9a }

  condition:
    any of them
}