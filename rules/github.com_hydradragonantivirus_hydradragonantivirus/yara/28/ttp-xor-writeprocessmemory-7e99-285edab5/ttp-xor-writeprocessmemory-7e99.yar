rule TTP_XOR_WriteProcessMemory_7e99 {
  strings:
    $key_7e99 = { 29 eb [2] 1b c9 [2] 1d fc [2] 33 fc [2] 0c e0 }

  condition:
    any of them
}