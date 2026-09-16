rule TTP_XOR_WriteProcessMemory_ee04 {
  strings:
    $key_ee04 = { b9 76 [2] 8b 54 [2] 8d 61 [2] a3 61 [2] 9c 7d }

  condition:
    any of them
}