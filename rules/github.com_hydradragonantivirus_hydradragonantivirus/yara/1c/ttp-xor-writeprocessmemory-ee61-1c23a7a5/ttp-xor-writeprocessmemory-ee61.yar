rule TTP_XOR_WriteProcessMemory_ee61 {
  strings:
    $key_ee61 = { b9 13 [2] 8b 31 [2] 8d 04 [2] a3 04 [2] 9c 18 }

  condition:
    any of them
}