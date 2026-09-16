rule TTP_XOR_WriteProcessMemory_ee74 {
  strings:
    $key_ee74 = { b9 06 [2] 8b 24 [2] 8d 11 [2] a3 11 [2] 9c 0d }

  condition:
    any of them
}