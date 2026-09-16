rule TTP_XOR_WriteProcessMemory_0e99 {
  strings:
    $key_0e99 = { 59 eb [2] 6b c9 [2] 6d fc [2] 43 fc [2] 7c e0 }

  condition:
    any of them
}