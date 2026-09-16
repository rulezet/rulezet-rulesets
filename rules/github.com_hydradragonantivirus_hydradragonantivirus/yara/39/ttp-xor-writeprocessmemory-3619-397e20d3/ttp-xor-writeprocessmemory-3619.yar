rule TTP_XOR_WriteProcessMemory_3619 {
  strings:
    $key_3619 = { 61 6b [2] 53 49 [2] 55 7c [2] 7b 7c [2] 44 60 }

  condition:
    any of them
}