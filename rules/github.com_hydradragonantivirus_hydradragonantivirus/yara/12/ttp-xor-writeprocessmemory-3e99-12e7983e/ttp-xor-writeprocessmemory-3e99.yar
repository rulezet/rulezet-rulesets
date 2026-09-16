rule TTP_XOR_WriteProcessMemory_3e99 {
  strings:
    $key_3e99 = { 69 eb [2] 5b c9 [2] 5d fc [2] 73 fc [2] 4c e0 }

  condition:
    any of them
}