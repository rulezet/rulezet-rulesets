rule TTP_XOR_WriteProcessMemory_eefa {
  strings:
    $key_eefa = { b9 88 [2] 8b aa [2] 8d 9f [2] a3 9f [2] 9c 83 }

  condition:
    any of them
}