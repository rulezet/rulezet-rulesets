rule TTP_XOR_WriteProcessMemory_6afa {
  strings:
    $key_6afa = { 3d 88 [2] 0f aa [2] 09 9f [2] 27 9f [2] 18 83 }

  condition:
    any of them
}