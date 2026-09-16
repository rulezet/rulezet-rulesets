rule TTP_XOR_WriteProcessMemory_0439 {
  strings:
    $key_0439 = { 53 4b [2] 61 69 [2] 67 5c [2] 49 5c [2] 76 40 }

  condition:
    any of them
}