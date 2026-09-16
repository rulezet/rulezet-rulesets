rule TTP_XOR_WriteProcessMemory_cafa {
  strings:
    $key_cafa = { 9d 88 [2] af aa [2] a9 9f [2] 87 9f [2] b8 83 }

  condition:
    any of them
}