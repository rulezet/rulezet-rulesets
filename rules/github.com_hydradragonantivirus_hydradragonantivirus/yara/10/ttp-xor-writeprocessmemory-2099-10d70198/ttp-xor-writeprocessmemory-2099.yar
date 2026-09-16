rule TTP_XOR_WriteProcessMemory_2099 {
  strings:
    $key_2099 = { 77 eb [2] 45 c9 [2] 43 fc [2] 6d fc [2] 52 e0 }

  condition:
    any of them
}