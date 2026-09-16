rule TTP_XOR_WriteProcessMemory_04ed {
  strings:
    $key_04ed = { 53 9f [2] 61 bd [2] 67 88 [2] 49 88 [2] 76 94 }

  condition:
    any of them
}