rule TTP_XOR_WriteProcessMemory_ee78 {
  strings:
    $key_ee78 = { b9 0a [2] 8b 28 [2] 8d 1d [2] a3 1d [2] 9c 01 }

  condition:
    any of them
}