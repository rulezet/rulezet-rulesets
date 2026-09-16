rule TTP_XOR_WriteProcessMemory_fc99 {
  strings:
    $key_fc99 = { ab eb [2] 99 c9 [2] 9f fc [2] b1 fc [2] 8e e0 }

  condition:
    any of them
}