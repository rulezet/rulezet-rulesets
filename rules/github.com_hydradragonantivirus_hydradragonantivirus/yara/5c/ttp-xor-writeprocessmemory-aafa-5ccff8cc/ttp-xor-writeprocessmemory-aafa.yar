rule TTP_XOR_WriteProcessMemory_aafa {
  strings:
    $key_aafa = { fd 88 [2] cf aa [2] c9 9f [2] e7 9f [2] d8 83 }

  condition:
    any of them
}