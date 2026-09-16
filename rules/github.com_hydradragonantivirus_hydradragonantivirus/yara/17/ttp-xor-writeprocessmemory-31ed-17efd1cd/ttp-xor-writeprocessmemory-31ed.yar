rule TTP_XOR_WriteProcessMemory_31ed {
  strings:
    $key_31ed = { 66 9f [2] 54 bd [2] 52 88 [2] 7c 88 [2] 43 94 }

  condition:
    any of them
}