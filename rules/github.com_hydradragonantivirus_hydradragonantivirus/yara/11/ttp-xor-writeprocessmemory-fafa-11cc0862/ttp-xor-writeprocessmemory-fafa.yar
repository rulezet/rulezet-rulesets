rule TTP_XOR_WriteProcessMemory_fafa {
  strings:
    $key_fafa = { ad 88 [2] 9f aa [2] 99 9f [2] b7 9f [2] 88 83 }

  condition:
    any of them
}