rule TTP_XOR_WriteProcessMemory_ee99 {
  strings:
    $key_ee99 = { b9 eb [2] 8b c9 [2] 8d fc [2] a3 fc [2] 9c e0 }

  condition:
    any of them
}