rule TTP_XOR_WriteProcessMemory_0efa {
  strings:
    $key_0efa = { 59 88 [2] 6b aa [2] 6d 9f [2] 43 9f [2] 7c 83 }

  condition:
    any of them
}