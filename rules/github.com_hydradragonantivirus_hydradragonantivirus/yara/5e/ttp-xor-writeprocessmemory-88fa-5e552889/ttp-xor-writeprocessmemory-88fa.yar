rule TTP_XOR_WriteProcessMemory_88fa {
  strings:
    $key_88fa = { df 88 [2] ed aa [2] eb 9f [2] c5 9f [2] fa 83 }

  condition:
    any of them
}