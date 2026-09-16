rule TTP_XOR_WriteProcessMemory_efe8 {
  strings:
    $key_efe8 = { b8 9a [2] 8a b8 [2] 8c 8d [2] a2 8d [2] 9d 91 }

  condition:
    any of them
}