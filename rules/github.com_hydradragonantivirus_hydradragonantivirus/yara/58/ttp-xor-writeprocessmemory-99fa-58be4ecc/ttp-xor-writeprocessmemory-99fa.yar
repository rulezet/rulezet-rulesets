rule TTP_XOR_WriteProcessMemory_99fa {
  strings:
    $key_99fa = { ce 88 [2] fc aa [2] fa 9f [2] d4 9f [2] eb 83 }

  condition:
    any of them
}